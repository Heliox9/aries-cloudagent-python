import asyncio
import json
import logging
import os
import sys
import time
import datetime

from aiohttp import ClientError
from qrcode import QRCode

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


class EnrollmentAgent(AriesAgent):
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
            prefix="Enrollment",
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

    async def detect_connection(self):
        await self._connection_ready
        self._connection_ready = None

    @property
    def connection_ready(self):
        return self._connection_ready.done() and self._connection_ready.result()

    def generate_credential_offer(self, aip, cred_type, cred_def_id, exchange_tracing):
        d = datetime.date.today()
        birth_date = datetime.date(d.year - 25, d.month, d.day)
        start_date = datetime.date(d.year - 1, d.month, d.day)
        end_date = datetime.date(d.year + 1, d.month, d.day)
        date_format = "%Y%m%d"

        # define attributes to send for credential
        self.cred_attrs[cred_def_id] = {
            "name": "Alice Smith",
            "date": d.strftime(date_format),
            "degree": "CS",
            "birthdate_dateint": birth_date.strftime(date_format),
            "start_date": start_date.strftime(date_format),
            "end_date": end_date.strftime(date_format),
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
            if cred_type == CRED_FORMAT_INDY:
                offer_request = {
                    "connection_id": self.connection_id,
                    "comment": f"Offer on cred def id {cred_def_id}",
                    "auto_remove": False,
                    "credential_preview": cred_preview,
                    "filter": {"indy": {"cred_def_id": cred_def_id}},
                    "trace": exchange_tracing,
                }
                return offer_request

            elif cred_type == CRED_FORMAT_JSON_LD:
                # JH TODO adjust for new patterns or remove entirely
                log_status(
                    "DEPRECATED: this part of credential generation has not been updated for new patterns. FIX BEFORE USE")
                offer_request = {
                    "connection_id": self.connection_id,
                    "filter": {
                        "ld_proof": {
                            "credential": {
                                "@context": [
                                    "https://www.w3.org/2018/credentials/v1",
                                    "https://w3id.org/citizenship/v1",
                                    "https://w3id.org/security/bbs/v1",
                                ],
                                "type": [
                                    "VerifiableCredential",
                                    "PermanentResident",
                                ],
                                "id": "https://credential.example.com/residents/1234567890",
                                "issuer": self.did,
                                "issuanceDate": "2020-01-01T12:00:00Z",
                                "credentialSubject": {
                                    "type": ["PermanentResident"],
                                    "givenName": "ALICE",
                                    "familyName": "SMITH",
                                    "gender": "Female",
                                    "birthCountry": "Bahamas",
                                    "birthDate": "1958-07-17",
                                },
                            },
                            "options": {"proofType": SIG_TYPE_BLS},
                        }
                    },
                }
                return offer_request

            else:
                raise Exception(f"Error invalid credential type: {self.cred_type}")

        else:
            raise Exception(f"Error invalid AIP level: {self.aip}")

    def generate_proof_request_web_request(
            self, aip, cred_type, revocation, exchange_tracing, connectionless=False
    ):
        age = 18
        d = datetime.date.today()
        birth_date = datetime.date(d.year - age, d.month, d.day)
        birth_date_format = "%Y%m%d"

        if aip == 10 or (aip == 20 and cred_type == CRED_FORMAT_INDY):

            req_attrs = [
                {
                    "name": "name",
                    "restrictions": [{"schema_name": "enrollment schema"}],
                },
                {
                    "name": "date",
                    "restrictions": [{"schema_name": "enrollment schema"}],
                },
            ]
            if revocation:
                req_attrs.append(
                    {
                        "name": "degree",
                        "restrictions": [{"schema_name": "enrollment schema"}],
                        "non_revoked": {"to": int(time.time() - 1)},
                    },
                )
            else:
                req_attrs.append(
                    {
                        "name": "degree",
                        "restrictions": [{"schema_name": "enrollment schema"}],
                    }
                )

            #     JH TODO find out what self attested is and does
            if SELF_ATTESTED:
                # test self-attested claims
                req_attrs.append(
                    {"name": "self_attested_thing"},
                )
            req_preds = [
                # test zero-knowledge proofs
                {
                    "name": "birthdate_dateint",
                    "p_type": "<=",
                    "p_value": int(birth_date.strftime(birth_date_format)),
                    "restrictions": [{"schema_name": "enrollment schema"}],
                }
            ]
            indy_proof_request = {
                "name": "Proof of Education",
                "version": "1.0",
                "requested_attributes": {
                    f"0_{req_attr['name']}_uuid": req_attr for req_attr in req_attrs
                },
                "requested_predicates": {
                    f"0_{req_pred['name']}_GE_uuid": req_pred
                    for req_pred in req_preds
                },
            }

            if revocation:
                indy_proof_request["non_revoked"] = {"to": int(time.time())}

            if aip == 20:
                proof_request_web_request = {
                    "presentation_request": {"indy": indy_proof_request},
                    "trace": exchange_tracing,
                }
            else:
                proof_request_web_request = {
                    "proof_request": indy_proof_request,
                    "trace": exchange_tracing,
                }
            if not connectionless:
                proof_request_web_request["connection_id"] = self.connection_id
            return proof_request_web_request

        elif aip == 20 and cred_type == CRED_FORMAT_JSON_LD:
            # JH TODO adjust for new patterns or remove entirely
            log_status(
                "DEPRECATED: this part of credential generation has not been updated for new patterns. FIX BEFORE USE")

            proof_request_web_request = {
                "comment": "test proof request for json-ld",
                "presentation_request": {
                    "dif": {
                        "options": {
                            "challenge": "3fa85f64-5717-4562-b3fc-2c963f66afa7",
                            "domain": "4jt78h47fh47",
                        },
                        "presentation_definition": {
                            "id": "32f54163-7166-48f1-93d8-ff217bdb0654",
                            "format": {"ldp_vp": {"proof_type": [SIG_TYPE_BLS]}},
                            "input_descriptors": [
                                {
                                    "id": "citizenship_input_1",
                                    "name": "EU Driver's License",
                                    "schema": [
                                        {
                                            "uri": "https://www.w3.org/2018/credentials#VerifiableCredential"
                                        },
                                        {
                                            "uri": "https://w3id.org/citizenship#PermanentResident"
                                        },
                                    ],
                                    "constraints": {
                                        "limit_disclosure": "required",
                                        "is_holder": [
                                            {
                                                "directive": "required",
                                                "field_id": [
                                                    "1f44d55f-f161-4938-a659-f8026467f126"
                                                ],
                                            }
                                        ],
                                        "fields": [
                                            {
                                                "id": "1f44d55f-f161-4938-a659-f8026467f126",
                                                "path": [
                                                    "$.credentialSubject.familyName"
                                                ],
                                                "purpose": "The claim must be from one of the specified person",
                                                "filter": {"const": "SMITH"},
                                            },
                                            {
                                                "path": [
                                                    "$.credentialSubject.givenName"
                                                ],
                                                "purpose": "The claim must be from one of the specified person",
                                            },
                                        ],
                                    },
                                }
                            ],
                        },
                    }
                },
            }
            if not connectionless:
                proof_request_web_request["connection_id"] = self.connection_id
            return proof_request_web_request


        else:
            raise Exception(
                f"Error invalid AIP level,  credential type combination(aip: {self.aip} | cred: {self.cred_type}")


async def main(args):
    enrollment_agent = await create_agent_with_args(args, ident="enrollment")

    try:
        log_status(
            "#1 Provision an agent and wallet, get back configuration details"
            + (
                f" (Wallet type: {enrollment_agent.wallet_type})"
                if enrollment_agent.wallet_type
                else ""
            )
        )
        agent = EnrollmentAgent(
            "enrollment.agent",
            enrollment_agent.start_port,
            enrollment_agent.start_port + 1,
            genesis_data=enrollment_agent.genesis_txns,
            genesis_txn_list=enrollment_agent.genesis_txn_list,
            no_auto=enrollment_agent.no_auto,
            tails_server_base_url=enrollment_agent.tails_server_base_url,
            revocation=enrollment_agent.revocation,
            timing=enrollment_agent.show_timing,
            multitenant=enrollment_agent.multitenant,
            mediation=enrollment_agent.mediation,
            wallet_type=enrollment_agent.wallet_type,
            seed=enrollment_agent.seed,
            aip=enrollment_agent.aip,
            endorser_role=enrollment_agent.endorser_role,
            anoncreds_legacy_revocation=enrollment_agent.anoncreds_legacy_revocation,
        )

        enrollment_schema_name = "enrollment schema"
        enrollment_schema_attrs = [
            "name",  # name of student
            "date",  # date of generation
            "degree",  # majoring field
            "birthdate_dateint",  # birthdate of student
            "start_date",  # start date for enrollment
            "end_date",  # expected end date of enrollment
        ]
        if enrollment_agent.cred_type == CRED_FORMAT_INDY:
            enrollment_agent.public_did = True
            await enrollment_agent.initialize(
                the_agent=agent,
                schema_name=enrollment_schema_name,
                schema_attrs=enrollment_schema_attrs,
                create_endorser_agent=(enrollment_agent.endorser_role == "author")
                if enrollment_agent.endorser_role
                else False,
            )
        elif enrollment_agent.cred_type == CRED_FORMAT_JSON_LD:
            enrollment_agent.public_did = True
            await enrollment_agent.initialize(the_agent=agent)
        else:
            raise Exception("Invalid credential type:" + enrollment_agent.cred_type)

        # generate an invitation for Alice
        await enrollment_agent.generate_invitation(
            display_qr=False, display_invite=True, reuse_connections=enrollment_agent.reuse_connections, wait=True
        )

        exchange_tracing = False
        options = (
            "    (1) Issue Credential\n"
            "    (2) Send Proof Request\n"
            "    (3) Send Message\n"
            "    (4) Create New Invitation\n"
        )
        if enrollment_agent.revocation:
            # JH TODO test revocation features
            log_status("UNTESTED this functionality has not been tested since reworking")
            options += (
                "    (5) Revoke Credential\n"
                "    (6) Publish Revocations\n"
                "    (7) Rotate Revocation Registry\n"
                "    (8) List Revocation Registries\n"
            )
        if enrollment_agent.endorser_role and enrollment_agent.endorser_role == "author":
            options += "    (D) Set Endorser's DID\n"
        if enrollment_agent.multitenant:
            options += "    (W) Create and/or Enable Wallet\n"
        options += "    (T) Toggle tracing on credential/proof exchange\n"
        options += "    (X) Exit?\n[1/2/3/4/{}{}T/X] ".format(
            "5/6/7/8/" if enrollment_agent.revocation else "",
            "W/" if enrollment_agent.multitenant else "",
        )
        async for option in prompt_loop(options):
            if option is not None:
                option = option.strip()

            if option is None or option in "xX":
                break

            elif option in "dD" and enrollment_agent.endorser_role:
                endorser_did = await prompt("Enter Endorser's DID: ")
                await enrollment_agent.agent.admin_POST(
                    f"/transactions/{enrollment_agent.agent.connection_id}/set-endorser-info",
                    params={"endorser_did": endorser_did},
                )

            elif option in "wW" and enrollment_agent.multitenant:
                target_wallet_name = await prompt("Enter wallet name: ")
                include_subwallet_webhook = await prompt(
                    "(Y/N) Create sub-wallet webhook target: "
                )
                if include_subwallet_webhook.lower() == "y":
                    created = await enrollment_agent.agent.register_or_switch_wallet(
                        target_wallet_name,
                        webhook_port=enrollment_agent.agent.get_new_webhook_port(),
                        public_did=True,
                        mediator_agent=enrollment_agent.mediator_agent,
                        endorser_agent=enrollment_agent.endorser_agent,
                        taa_accept=enrollment_agent.taa_accept,
                    )
                else:
                    created = await enrollment_agent.agent.register_or_switch_wallet(
                        target_wallet_name,
                        public_did=True,
                        mediator_agent=enrollment_agent.mediator_agent,
                        endorser_agent=enrollment_agent.endorser_agent,
                        cred_type=enrollment_agent.cred_type,
                        taa_accept=enrollment_agent.taa_accept,
                    )
                # create a schema and cred def for the new wallet
                # TODO check first in case we are switching between existing wallets
                if created:
                    # TODO this fails because the new wallet doesn't get a public DID
                    await enrollment_agent.create_schema_and_cred_def(
                        schema_name=enrollment_schema_name,
                        schema_attrs=enrollment_schema_attrs,
                    )

            elif option in "tT":
                exchange_tracing = not exchange_tracing
                log_msg(
                    ">>> Credential/Proof Exchange Tracing is {}".format(
                        "ON" if exchange_tracing else "OFF"
                    )
                )

            elif option == "1":
                log_status("#13 Issue degree credential offer to Student")

                if enrollment_agent.aip == 10:
                    offer_request = enrollment_agent.agent.generate_credential_offer(
                        enrollment_agent.aip, None, enrollment_agent.cred_def_id, exchange_tracing
                    )
                    await enrollment_agent.agent.admin_POST(
                        "/issue-credential/send-offer", offer_request
                    )

                elif enrollment_agent.aip == 20:
                    if enrollment_agent.cred_type == CRED_FORMAT_INDY:
                        offer_request = enrollment_agent.agent.generate_credential_offer(
                            enrollment_agent.aip,
                            enrollment_agent.cred_type,
                            enrollment_agent.cred_def_id,
                            exchange_tracing,
                        )

                    elif enrollment_agent.cred_type == CRED_FORMAT_JSON_LD:
                        offer_request = enrollment_agent.agent.generate_credential_offer(
                            enrollment_agent.aip,
                            enrollment_agent.cred_type,
                            None,
                            exchange_tracing,
                        )

                    else:
                        raise Exception(
                            f"Error invalid credential type: {enrollment_agent.cred_type}"
                        )

                    await enrollment_agent.agent.admin_POST(
                        "/issue-credential-2.0/send-offer", offer_request
                    )

                else:
                    raise Exception(f"Error invalid AIP level: {enrollment_agent.aip}")

            elif option == "2":
                log_status("#20 Request proof of enrollment from student")
                if enrollment_agent.aip == 10:
                    proof_request_web_request = (
                        enrollment_agent.agent.generate_proof_request_web_request(
                            enrollment_agent.aip,
                            enrollment_agent.cred_type,
                            enrollment_agent.revocation,
                            exchange_tracing,
                        )
                    )
                    await enrollment_agent.agent.admin_POST(
                        "/present-proof/send-request", proof_request_web_request
                    )
                    pass

                elif enrollment_agent.aip == 20:
                    if enrollment_agent.cred_type == CRED_FORMAT_INDY or enrollment_agent.cred_type == CRED_FORMAT_JSON_LD:
                        proof_request_web_request = (
                            enrollment_agent.agent.generate_proof_request_web_request(
                                enrollment_agent.aip,
                                enrollment_agent.cred_type,
                                enrollment_agent.revocation,
                                exchange_tracing,
                            )
                        )

                    else:
                        raise Exception(
                            "Error invalid credential type:" + enrollment_agent.cred_type
                        )

                    log_status("#20X call send request endpoint")
                    await agent.admin_POST(
                        "/present-proof-2.0/send-request", proof_request_web_request
                    )

                else:
                    raise Exception(f"Error invalid AIP level: {enrollment_agent.aip}")



            elif option == "3":
                msg = await prompt("Enter message: ")
                await enrollment_agent.agent.admin_POST(
                    f"/connections/{enrollment_agent.agent.connection_id}/send-message",
                    {"content": msg},
                )

            elif option == "4":
                log_msg(
                    "Creating a new invitation, please receive "
                    "and accept this invitation using Alice agent"
                )
                await enrollment_agent.generate_invitation(
                    display_invite=True,
                    display_qr=False,
                    reuse_connections=enrollment_agent.reuse_connections,
                    wait=True,
                )

            elif option == "5" and enrollment_agent.revocation:
                rev_reg_id = (await prompt("Enter revocation registry ID: ")).strip()
                cred_rev_id = (await prompt("Enter credential revocation ID: ")).strip()
                publish = (
                              await prompt("Publish now? [Y/N]: ", default="N")
                          ).strip() in "yY"
                try:
                    await enrollment_agent.agent.admin_POST(
                        "/revocation/revoke",
                        {
                            "rev_reg_id": rev_reg_id,
                            "cred_rev_id": cred_rev_id,
                            "publish": publish,
                            "connection_id": enrollment_agent.agent.connection_id,
                            # leave out thread_id, let aca-py generate
                            # "thread_id": "12345678-4444-4444-4444-123456789012",
                            "comment": "Revocation reason goes here ...",
                        },
                    )
                except ClientError:
                    pass

            elif option == "6" and enrollment_agent.revocation:
                try:
                    resp = await enrollment_agent.agent.admin_POST(
                        "/revocation/publish-revocations", {}
                    )
                    enrollment_agent.agent.log(
                        "Published revocations for {} revocation registr{} {}".format(
                            len(resp["rrid2crid"]),
                            "y" if len(resp["rrid2crid"]) == 1 else "ies",
                            json.dumps([k for k in resp["rrid2crid"]], indent=4),
                        )
                    )
                except ClientError:
                    pass
            elif option == "7" and enrollment_agent.revocation:
                try:
                    resp = await enrollment_agent.agent.admin_POST(
                        f"/revocation/active-registry/{enrollment_agent.cred_def_id}/rotate",
                        {},
                    )
                    enrollment_agent.agent.log(
                        "Rotated registries for {}. Decommissioned Registries: {}".format(
                            enrollment_agent.cred_def_id,
                            json.dumps([r for r in resp["rev_reg_ids"]], indent=4),
                        )
                    )
                except ClientError:
                    pass
            elif option == "8" and enrollment_agent.revocation:
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
                    resp = await enrollment_agent.agent.admin_GET(
                        "/revocation/registries/created",
                        params={"state": state},
                    )
                    enrollment_agent.agent.log(
                        "Registries (state = '{}'): {}".format(
                            state,
                            json.dumps([r for r in resp["rev_reg_ids"]], indent=4),
                        )
                    )
                except ClientError:
                    pass

        if enrollment_agent.show_timing:
            timing = await enrollment_agent.agent.fetch_timing()
            if timing:
                for line in enrollment_agent.agent.format_timing(timing):
                    log_msg(line)

    finally:
        terminated = await enrollment_agent.terminate()

    await asyncio.sleep(0.1)

    if not terminated:
        os._exit(1)


if __name__ == "__main__":
    parser = arg_parser(ident="enrollment", port=8020)
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
                "Enrollment agent remote debugging to "
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
