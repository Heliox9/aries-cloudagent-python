import asyncio
import json
import logging
import os
import sys
import time
import datetime

from aiohttp import ClientError
from qrcode import QRCode

import random

from datetime import date
from uuid import uuid4

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from runners.agent_container import (  # noqa:E402
    arg_parser,
    create_agent_with_args,
    AriesAgent,
)
from runners.support.agent import (  # noqa:E402
    CRED_FORMAT_INDY,
    CRED_FORMAT_JSON_LD,
    SIG_TYPE_BLS,
)
from runners.support.utils import (  # noqa:E402
    log_msg,
    log_status,
    prompt,
    prompt_loop,
)

CRED_PREVIEW_TYPE = "https://didcomm.org/issue-credential/2.0/credential-preview"
SELF_ATTESTED = os.getenv("SELF_ATTESTED")
TAILS_FILE_COUNT = int(os.getenv("TAILS_FILE_COUNT", 100))

logging.basicConfig(level=logging.WARNING)
LOGGER = logging.getLogger(__name__)


class CompanyAgent(AriesAgent):
    def __init__(
            self,
            ident: str,
            http_port: int,
            admin_port: int,
            no_auto: bool = False,
            endorser_role: str = None,
            revocation: bool = False,
            anoncreds_legacy_revocation: str = None,
            **kwargs,
    ):
        super().__init__(
            ident,
            http_port,
            admin_port,
            prefix="Company",
            no_auto=no_auto,
            endorser_role=endorser_role,
            revocation=revocation,
            anoncreds_legacy_revocation=anoncreds_legacy_revocation,
            **kwargs,
        )
        self.connection_id = None
        self._connection_ready = None
        self.cred_state = {}
        # TODO define a dict to hold credential attributes
        # based on cred_def_id
        self.cred_attrs = {}
        self.last_proof_ok = False

    async def detect_connection(self):
        await self._connection_ready
        self._connection_ready = None

    @property
    def connection_ready(self):
        return self._connection_ready.done() and self._connection_ready.result()

    def generate_credential_offer(self, aip, cred_def_id, exchange_tracing):
        d = datetime.date.today()
        date_format = "%Y%m%d"

        # define attributes to send for credential
        self.cred_attrs[cred_def_id] = {
            "name": "Alice Smith",
            "start_date": d.strftime(date_format),
            "position": "Developer",
        }

        cred_preview = {
            "@type": CRED_PREVIEW_TYPE,
            "attributes": [
                {"name": n, "value": v}
                for (n, v) in self.cred_attrs[cred_def_id].items()
            ],
        }

        if aip == 10:

            offer_request = {
                "connection_id": self.connection_id,
                "cred_def_id": cred_def_id,
                "comment": f"Offer on cred def id {cred_def_id}",
                "auto_remove": False,
                "credential_preview": cred_preview,
                "trace": exchange_tracing,
            }
            return offer_request

        elif aip == 20:
            offer_request = {
                "connection_id": self.connection_id,
                "comment": f"Offer on cred def id {cred_def_id}",
                "auto_remove": False,
                "credential_preview": cred_preview,
                "filter": {"indy": {"cred_def_id": cred_def_id}},
                "trace": exchange_tracing,
            }
            return offer_request


        else:
            raise Exception(f"Error invalid AIP level: {self.aip}")

    async def handle_present_proof_v2_0(self, message):
        state = message["state"]
        pres_ex_id = message["pres_ex_id"]
        self.log(f"Presentation: state = {state}, pres_ex_id = {pres_ex_id}")

        if state == "presentation-received":
            #  handle received presentations
            self.log("#27 Process the proof provided by Student")
            self.log("#28 Check if proof is valid")
            proof = await self.admin_POST(
                f"/present-proof-2.0/records/{pres_ex_id}/verify-presentation"
            )

            verified_value = proof['verified'].lower() == 'true'
            self.log("Proof = ", verified_value)

            # if presentation is a enrollment schema (proof of education),
            # check values received
            pres_req = message["by_format"]["pres_request"]["indy"]
            pres = message["by_format"]["pres"]["indy"]
            is_proof_of_education = (
                    pres_req["name"] == "Proof of Education"
            )
            self.log("Education = ", is_proof_of_education)
            if is_proof_of_education and verified_value:
                self.log("#28.1 Received proof of education, check claims")

                checks = []
                additional = 0
                # JH check claims in actual logic
                for (referent, attr_spec) in pres_req["requested_attributes"].items():
                    log_attribute(referent, pres, attr_spec)
                    # NOTE: Switch case not possible due to python version 3.9 and switch case requires 3.10
                    name = attr_spec['name']
                    if name == "name":
                        checks.append(check_attr_value(pres, referent, "Alice Smith"))
                    elif name == "degree":
                        checks.append(check_attr_value(pres, referent, "CS"))
                    else:
                        self.log("attribute not checked")
                        additional += 1

                for id_spec in pres["identifiers"]:
                    # just print out the schema/cred def id's of presented claims
                    self.log(f"schema_id: {id_spec['schema_id']}")
                    self.log(f"cred_def_id {id_spec['cred_def_id']}")

                self.log(checks)
                self.last_proof_ok = (False not in checks)
                self.log(f"checked {len(checks)} values ({additional} additional unchecked)")
                self.log(f"value check complete, setting proof value to {self.last_proof_ok}")
            else:
                self.log("not validating proof values because it is not educational or not verified")
                self.log(f"verified text: {proof['verified']} | value: {verified_value}")
                # in case there are any other kinds of proofs received
                self.log("#28.1 Received ", pres_req["name"])
                self.last_proof_ok = False
        elif state == "abandoned":
            self.last_proof_ok = False
            self.log(f"proofing abandoned (possibly failed ZKP) setting proof value to {self.last_proof_ok}")
            self.log(f"check student log for failure messages on ZKP")


def log_attribute(referent, pres, attr_spec):
    if referent in pres['requested_proof']['revealed_attrs']:
        log_status(
            f"{attr_spec['name']}: "
            f"{pres['requested_proof']['revealed_attrs'][referent]['raw']}"
        )
    else:
        log_status(
            f"{attr_spec['name']}: "
            "(attribute not revealed)"
        )


def check_attr_value(pres, referent, expected_value):
    try:
        actual = pres['requested_proof']['revealed_attrs'][referent]['raw']
        match = (actual == expected_value)

        if not match:
            log_status(f"value check failed, expected: {expected_value} actual: {actual}")
    except Exception as err:
        match = False
        log_status("Error occured while checking attribute value")
        log_status(f"Error: \n{err}")

    return match


async def main(args):
    company_agent = await create_agent_with_args(args, ident="company")

    try:
        log_status(
            "#1 Provision an agent and wallet, get back configuration details"
            + (
                f" (Wallet type: {company_agent.wallet_type})"
                if company_agent.wallet_type
                else ""
            )
        )
        agent = CompanyAgent(
            "company.agent",
            company_agent.start_port,
            company_agent.start_port + 1,
            genesis_data=company_agent.genesis_txns,
            genesis_txn_list=company_agent.genesis_txn_list,
            no_auto=company_agent.no_auto,
            tails_server_base_url=company_agent.tails_server_base_url,
            revocation=company_agent.revocation,
            timing=company_agent.show_timing,
            multitenant=company_agent.multitenant,
            mediation=company_agent.mediation,
            wallet_type=company_agent.wallet_type,
            seed=company_agent.seed,
            aip=company_agent.aip,
            endorser_role=company_agent.endorser_role,
            anoncreds_legacy_revocation=company_agent.anoncreds_legacy_revocation,
        )

        job_schema_name = "job schema"
        job_schema_attrs = [
            "name",
            "start_date",
            "position",
        ]
        if company_agent.cred_type == CRED_FORMAT_INDY:
            company_agent.public_did = True
            await company_agent.initialize(
                the_agent=agent,
                schema_name=job_schema_name,
                schema_attrs=job_schema_attrs,
                create_endorser_agent=(company_agent.endorser_role == "author")
                if company_agent.endorser_role
                else False,
            )
        elif company_agent.cred_type == CRED_FORMAT_JSON_LD:
            company_agent.public_did = True
            await company_agent.initialize(the_agent=agent)
        else:
            raise Exception("Invalid credential type:" + company_agent.cred_type)

        # generate an invitation for Student
        await company_agent.generate_invitation(
            display_qr=False, display_invite=True, reuse_connections=company_agent.reuse_connections, wait=True
        )

        exchange_tracing = False
        options = (
            "    (1) Issue Credential\n"
            "    (2) Send Proof Request\n"
            "    (3) Send Message\n"
            "    (4) Create New Invitation\n"
        )
        if company_agent.revocation:
            options += (
                "    (5) Revoke Credential\n"
                "    (6) Publish Revocations\n"
                "    (7) Rotate Revocation Registry\n"
                "    (8) List Revocation Registries\n"
            )
        if company_agent.endorser_role and company_agent.endorser_role == "author":
            log_status("WARNING Untested feature")
            options += "    (D) Set Endorser's DID\n"
        if company_agent.multitenant:
            log_status("WARNING Untested feature")
            options += "    (W) Create and/or Enable Wallet\n"
        options += "    (T) Toggle tracing on credential/proof exchange\n"
        options += "    (X) Exit?\n[1/2/3/4/{}{}T/X] ".format(
            "5/6/7/8/" if company_agent.revocation else "",
            "W/" if company_agent.multitenant else "",
        )
        async for option in prompt_loop(options):
            if option is not None:
                # cuts additional whitespaces
                option = option.strip()

            if option is None or option in "xX":
                # stops execution loop
                break

            elif option in "dD" and company_agent.endorser_role:
                # JH TODO IDK
                log_status("WARNING Untested feature")
                endorser_did = await prompt("Enter Endorser's DID: ")
                await company_agent.agent.admin_POST(
                    f"/transactions/{company_agent.agent.connection_id}/set-endorser-info",
                    params={"endorser_did": endorser_did},
                )

            elif option in "wW" and company_agent.multitenant:
                # JH TODO IDK
                log_status("WARNING Untested feature")
                target_wallet_name = await prompt("Enter wallet name: ")
                include_subwallet_webhook = await prompt(
                    "(Y/N) Create sub-wallet webhook target: "
                )
                if include_subwallet_webhook.lower() == "y":
                    created = await company_agent.agent.register_or_switch_wallet(
                        target_wallet_name,
                        webhook_port=company_agent.agent.get_new_webhook_port(),
                        public_did=True,
                        mediator_agent=company_agent.mediator_agent,
                        endorser_agent=company_agent.endorser_agent,
                        taa_accept=company_agent.taa_accept,
                    )
                else:
                    created = await company_agent.agent.register_or_switch_wallet(
                        target_wallet_name,
                        public_did=True,
                        mediator_agent=company_agent.mediator_agent,
                        endorser_agent=company_agent.endorser_agent,
                        cred_type=company_agent.cred_type,
                        taa_accept=company_agent.taa_accept,
                    )
                # create a schema and cred def for the new wallet
                # TODO check first in case we are switching between existing wallets
                if created:
                    # TODO this fails because the new wallet doesn't get a public DID
                    await company_agent.create_schema_and_cred_def(
                        schema_name=job_schema_name,
                        schema_attrs=job_schema_attrs,
                    )

            elif option in "tT":
                exchange_tracing = not exchange_tracing
                log_msg(
                    ">>> Credential/Proof Exchange Tracing is {}".format(
                        "ON" if exchange_tracing else "OFF"
                    )
                )

            elif option == "1":
                if company_agent.agent.last_proof_ok:
                    log_status("1: offering credential with student status")
                    await offer_credential(company_agent, exchange_tracing)
                else:
                    log_status("1.2: Diploma is necessary to be accepted to this position")
            elif option == "2":
                log_status("#20 Request proof of enrollment from student")
                #  presentation requests
                log_status("invalidating previous proof")
                agent.last_proof_ok = False

                # set the required attributes for proofing a provided VC
                # JH NOTES the first attribute is not revealed by the base agent implementation
                req_attrs = [
                    {
                        "name": "date",
                        "restrictions": [{"schema_name": "diploma schema"}]
                    },
                    {
                        "name": "name",  # The name of the attribute
                        "restrictions": [{"schema_name": "diploma schema"}]
                        # restriction for the attribute, in this case the schema it has to belong to
                    },
                    {
                        "name": "degree",  # The name of the attribute
                        "restrictions": [{"schema_name": "diploma schema"}]
                        # restriction for the attribute, in this case the schema it has to belong to
                    },
                ]
                # set the required predicates
                # JH NOTES check what predicates actually do and how they differ from attributes
                # working theory: predicates are partials or what is usually referred to in zkp context (CORRECT https://yunxi-zhang-75627.medium.com/hyperledger-aries-aca-py-agents-setup-and-running-tutorials-part-vii-proof-request-reveal-and-8e3b86246578)

                # sanity check start date and issue date before current date
                d = datetime.date.today()
                date_format = "%Y%m%d"
                req_preds = [
                    {
                        "name": "grade",
                        "p_type": "<=",
                        "p_value": int("3"),
                        "restrictions": [{"schema_name": "diploma schema"}],
                    },

                ]

                # build the proof request necessary for the indy backend
                indy_proof_request = {
                    "name": "Proof of Education",
                    "version": "1.0",
                    "nonce": str(uuid4().int),
                    "requested_attributes": {
                        f"0_{req_attr['name']}_uuid": req_attr
                        for req_attr in req_attrs
                    },
                    "requested_predicates": {
                        f"0_{req_pred['name']}_GE_uuid": req_pred
                        for req_pred in req_preds
                    }
                }

                # package indy request to be sent to the ACA-Py agent which can access the hyperledger
                proof_request_web_request = {
                    "connection_id": agent.connection_id,
                    "presentation_request": {"indy": indy_proof_request},
                }

                # send the request to our agent, which forwards it to the connected agent
                # (based on the connection_id)
                log_status("20.1 posting present proof 2.0")
                proof_reply = await agent.admin_POST(
                    "/present-proof-2.0/send-request",
                    proof_request_web_request
                )
                # log_status(f"proof reply: {proof_reply}")

                log_status("proofing sequence complete. credential offer can be attempted")

            elif option == "3":
                log_status("starting direct messaging to connected agent")
                msg = await prompt("Enter message: ")
                await company_agent.agent.admin_POST(
                    f"/connections/{company_agent.agent.connection_id}/send-message",
                    {"content": msg},
                )

            elif option == "4":
                log_msg(
                    "Creating a new invitation, please receive "
                    "and accept this invitation using Student agent"
                )
                await company_agent.generate_invitation(
                    display_invite=True,
                    display_qr=False,
                    reuse_connections=company_agent.reuse_connections,
                    wait=True,
                )

            elif option == "5" and company_agent.revocation:
                # JH TODO actually test and use revocation
                log_status("WARNING Untested feature")
                rev_reg_id = (await prompt("Enter revocation registry ID: ")).strip()
                cred_rev_id = (await prompt("Enter credential revocation ID: ")).strip()
                publish = (
                              await prompt("Publish now? [Y/N]: ", default="N")
                          ).strip() in "yY"
                try:
                    await company_agent.agent.admin_POST(
                        "/revocation/revoke",
                        {
                            "rev_reg_id": rev_reg_id,
                            "cred_rev_id": cred_rev_id,
                            "publish": publish,
                            "connection_id": company_agent.agent.connection_id,
                            # leave out thread_id, let aca-py generate
                            # "thread_id": "12345678-4444-4444-4444-123456789012",
                            "comment": "Revocation reason goes here ...",
                        },
                    )
                except ClientError:
                    pass

            elif option == "6" and company_agent.revocation:
                log_status("WARNING Untested feature")
                try:
                    resp = await company_agent.agent.admin_POST(
                        "/revocation/publish-revocations", {}
                    )
                    company_agent.agent.log(
                        "Published revocations for {} revocation registr{} {}".format(
                            len(resp["rrid2crid"]),
                            "y" if len(resp["rrid2crid"]) == 1 else "ies",
                            json.dumps([k for k in resp["rrid2crid"]], indent=4),
                        )
                    )
                except ClientError:
                    pass
            elif option == "7" and company_agent.revocation:
                log_status("WARNING Untested feature")
                try:
                    resp = await company_agent.agent.admin_POST(
                        f"/revocation/active-registry/{company_agent.cred_def_id}/rotate",
                        {},
                    )
                    company_agent.agent.log(
                        "Rotated registries for {}. Decommissioned Registries: {}".format(
                            company_agent.cred_def_id,
                            json.dumps([r for r in resp["rev_reg_ids"]], indent=4),
                        )
                    )
                except ClientError:
                    pass
            elif option == "8" and company_agent.revocation:
                log_status("WARNING Untested feature")
                states = [
                    "init",
                    "generated",
                    "posted",
                    "active",
                    "full",
                    "decommissioned",
                ]
                state = (
                    await prompt(
                        f"Filter by state: {states}: ",
                        default="active",
                    )
                ).strip()
                if state not in states:
                    state = "active"
                try:
                    resp = await company_agent.agent.admin_GET(
                        "/revocation/registries/created",
                        params={"state": state},
                    )
                    company_agent.agent.log(
                        "Registries (state = '{}'): {}".format(
                            state,
                            json.dumps([r for r in resp["rev_reg_ids"]], indent=4),
                        )
                    )
                except ClientError:
                    pass

        # JH TODO find out when show_timing is set and what this logging could be useful for (stems from agent container directly)
        if company_agent.show_timing:
            timing = await company_agent.agent.fetch_timing()
            if timing:
                for line in company_agent.agent.format_timing(timing):
                    log_msg(line)

    finally:
        terminated = await company_agent.terminate()

    await asyncio.sleep(0.1)

    if not terminated:
        os._exit(1)


async def offer_credential(gym_agent, exchange_tracing):
    # Helper function which calls the credential offer endpoint with static credentials packaged inside the agent implementation
    log_status("#13 Issue credential offer to X")

    offer_request = gym_agent.agent.generate_credential_offer(
        gym_agent.aip, gym_agent.cred_def_id, exchange_tracing
    )
    await gym_agent.agent.admin_POST(
        "/issue-credential-2.0/send-offer", offer_request
    )


if __name__ == "__main__":
    parser = arg_parser(ident="gym", port=8090)
    args = parser.parse_args()

    ENABLE_PYDEVD_PYCHARM = os.getenv("ENABLE_PYDEVD_PYCHARM", "").lower()
    ENABLE_PYDEVD_PYCHARM = ENABLE_PYDEVD_PYCHARM and ENABLE_PYDEVD_PYCHARM not in (
        "false",
        "0",
    )
    PYDEVD_PYCHARM_HOST = os.getenv("PYDEVD_PYCHARM_HOST", "localhost")
    PYDEVD_PYCHARM_CONTROLLER_PORT = int(
        os.getenv("PYDEVD_PYCHARM_CONTROLLER_PORT", 5001)
    )

    if ENABLE_PYDEVD_PYCHARM:
        try:
            import pydevd_pycharm

            print(
                "GYM remote debugging to "
                f"{PYDEVD_PYCHARM_HOST}:{PYDEVD_PYCHARM_CONTROLLER_PORT}"
            )
            pydevd_pycharm.settrace(
                host=PYDEVD_PYCHARM_HOST,
                port=PYDEVD_PYCHARM_CONTROLLER_PORT,
                stdoutToServer=True,
                stderrToServer=True,
                suspend=False,
            )
        except ImportError:
            print("pydevd_pycharm library was not found")

    try:
        asyncio.get_event_loop().run_until_complete(main(args))
    except KeyboardInterrupt:
        os._exit(1)
