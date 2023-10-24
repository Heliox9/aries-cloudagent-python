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


class DiplomaAgent(AriesAgent):
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
            prefix="Diploma",
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

    async def check_proof_degree(self):
        self.log("checking proof for degree vc")
        if self.aip == 10:

            log_status("AIP 1.0 not maintained. possibly not supported")
            degree_proof_request = (
                self.agent.generate_proof_request_degree(
                    self.aip,
                    self.cred_type,
                    self.revocation,
                    exchange_tracing,
                )
            )
            await self.agent.admin_POST(
                "/present-proof/send-request", degree_proof_request
            )
            pass

        elif self.aip == 20:
            if self.cred_type == CRED_FORMAT_INDY:
                degree_proof_request = (
                    self.agent.generate_proof_request_degree(
                        self.aip,
                        self.cred_type,
                        self.revocation,
                        exchange_tracing,
                    )
                )

            elif self.cred_type == CRED_FORMAT_JSON_LD:
                degree_proof_request = (
                    self.agent.generate_proof_request_degree(
                        self.aip,
                        self.cred_type,
                        self.revocation,
                        exchange_tracing,
                    )
                )

            else:
                raise Exception(
                    "Error invalid credential type:" + self.cred_type
                )

            reply = await agent.admin_POST(
                "/present-proof-2.0/send-request", degree_proof_request
            )

            self.log(reply)

        #     JH TODO return proof value

        else:
            raise Exception(f"Error invalid AIP level: {diploma_agent.aip}")

    def generate_proof_request_degree(
            self, aip, cred_type, revocation, exchange_tracing, connectionless=False
    ):
        age = 18
        d = datetime.date.today()
        birth_date = datetime.date(d.year - age, d.month, d.day)
        birth_date_format = "%Y%m%d"
        if aip == 10:
            req_attrs = [
                {
                    "name": "name",
                    "restrictions": [{"schema_name": "degree schema"}],
                },
                {
                    "name": "date",
                    "restrictions": [{"schema_name": "degree schema"}],
                },
            ]
            if revocation:
                req_attrs.append(
                    {
                        "name": "degree",
                        "restrictions": [{"schema_name": "degree schema"}],
                        "non_revoked": {"to": int(time.time() - 1)},
                    },
                )
            else:
                req_attrs.append(
                    {
                        "name": "degree",
                        "restrictions": [{"schema_name": "degree schema"}],
                    }
                )
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
                    "restrictions": [{"schema_name": "degree schema"}],
                }
            ]
            indy_proof_request = {
                "name": "Proof of Education",
                "version": "1.0",
                "requested_attributes": {
                    f"0_{req_attr['name']}_uuid": req_attr for req_attr in req_attrs
                },
                "requested_predicates": {
                    f"0_{req_pred['name']}_GE_uuid": req_pred for req_pred in req_preds
                },
            }

            if revocation:
                indy_proof_request["non_revoked"] = {"to": int(time.time())}

            proof_request_web_request = {
                "proof_request": indy_proof_request,
                "trace": exchange_tracing,
            }
            if not connectionless:
                proof_request_web_request["connection_id"] = self.connection_id
            return proof_request_web_request

        elif aip == 20:
            if cred_type == CRED_FORMAT_INDY:
                req_attrs = [
                    {
                        "name": "name",
                        "restrictions": [{"schema_name": "degree schema"}],
                    },
                    {
                        "name": "date",
                        "restrictions": [{"schema_name": "degree schema"}],
                    },
                ]
                if revocation:
                    req_attrs.append(
                        {
                            "name": "degree",
                            "restrictions": [{"schema_name": "degree schema"}],
                            "non_revoked": {"to": int(time.time() - 1)},
                        },
                    )
                else:
                    req_attrs.append(
                        {
                            "name": "degree",
                            "restrictions": [{"schema_name": "degree schema"}],
                        }
                    )
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
                        "restrictions": [{"schema_name": "degree schema"}],
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

                proof_request_web_request = {
                    "presentation_request": {"indy": indy_proof_request},
                    "trace": exchange_tracing,
                }
                if not connectionless:
                    proof_request_web_request["connection_id"] = self.connection_id
                return proof_request_web_request

            elif cred_type == CRED_FORMAT_JSON_LD:
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
                raise Exception(f"Error invalid credential type: {self.cred_type}")

        else:
            raise Exception(f"Error invalid AIP level: {self.aip}")

    def generate_credential_offer(self, aip, cred_type, cred_def_id, exchange_tracing):

        if aip == 10:
            # JH: Notes: everything here has to be a valid string
            # define attributes to send for credential
            self.cred_attrs[cred_def_id] = {
                "name": "Alice Smith",
                "date": "2018-05-28",
                "degree": "Maths",
                "grade": "1.0",
            }

            cred_preview = {
                "@type": CRED_PREVIEW_TYPE,
                "attributes": [
                    {"name": n, "value": v}
                    for (n, v) in self.cred_attrs[cred_def_id].items()
                ],
            }
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
                self.cred_attrs[cred_def_id] = {
                    "name": "Alice Smith",
                    "date": "2018-05-28",
                    "degree": "Maths",
                    "grade": "2.0",
                }

                cred_preview = {
                    "@type": CRED_PREVIEW_TYPE,
                    "attributes": [
                        {"name": n, "value": v}
                        for (n, v) in self.cred_attrs[cred_def_id].items()
                    ],
                }
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
                raise Exception(f"Error invalid credential type: {self.cred_type}")

        else:
            raise Exception(f"Error invalid AIP level: {self.aip}")

    def generate_proof_request_web_request(
            self, aip, cred_type, revocation, exchange_tracing, connectionless=False
    ):
        self.log("genearting proof request body")
        if aip == 10:
            req_attrs = [
                {
                    "name": "name",
                    "restrictions": [{"schema_name": "diploma schema"}],
                },
                {
                    "name": "date",
                    "restrictions": [{"schema_name": "diploma schema"}],
                },
            ]
            if revocation:
                req_attrs.append(
                    {
                        "name": "degree",
                        "restrictions": [{"schema_name": "diploma schema"}],
                        "non_revoked": {"to": int(time.time() - 1)},
                    },
                )
            else:
                req_attrs.append(
                    {
                        "name": "degree",
                        "restrictions": [{"schema_name": "diploma schema"}],
                    }
                )
            if SELF_ATTESTED:
                # test self-attested claims
                req_attrs.append(
                    {"name": "self_attested_thing"},
                )
            req_preds = [
                # test zero-knowledge proofs
                # {
                #     "name": "birthdate_dateint",
                #     "p_type": "<=",
                #     "p_value": int(birth_date.strftime(birth_date_format)),
                #     "restrictions": [{"schema_name": "diploma schema"}],
                # }
            ]
            indy_proof_request = {
                "name": "Proof of Education",
                "version": "1.0",
                "requested_attributes": {
                    f"0_{req_attr['name']}_uuid": req_attr for req_attr in req_attrs
                },
                "requested_predicates": {
                    # f"0_{req_pred['name']}_GE_uuid": req_pred for req_pred in req_preds
                },
            }

            if revocation:
                indy_proof_request["non_revoked"] = {"to": int(time.time())}

            proof_request_web_request = {
                "proof_request": indy_proof_request,
                "trace": exchange_tracing,
            }
            if not connectionless:
                proof_request_web_request["connection_id"] = self.connection_id
            return proof_request_web_request

        elif aip == 20:
            if cred_type == CRED_FORMAT_INDY:
                req_attrs = [
                    {
                        "name": "name",
                        "restrictions": [{"schema_name": "diploma schema"}],
                    },
                    {
                        "name": "date",
                        "restrictions": [{"schema_name": "diploma schema"}],
                    },
                ]
                if revocation:
                    req_attrs.append(
                        {
                            "name": "degree",
                            "restrictions": [{"schema_name": "diploma schema"}],
                            "non_revoked": {"to": int(time.time() - 1)},
                        },
                    )
                else:
                    req_attrs.append(
                        {
                            "name": "degree",
                            "restrictions": [{"schema_name": "diploma schema"}],
                        }
                    )
                if SELF_ATTESTED:
                    # test self-attested claims
                    req_attrs.append(
                        {"name": "self_attested_thing"},
                    )

                self.log(req_attrs)
                # TODO see how to use this correctly
                req_preds = [
                    # test zero-knowledge proofs
                    # {
                    #     "name": "grade",
                    #     "p_type": "<=",
                    #     "p_value": float("4.0"),
                    #     "restrictions": [{"schema_name": "diploma schema"}],
                    # }
                ]
                indy_proof_request = {
                    "name": "Proof of Education",
                    "version": "1.0",
                    "requested_attributes": {
                        f"0_{req_attr['name']}_uuid": req_attr for req_attr in req_attrs
                    },
                    "requested_predicates": {
                        # f"0_{req_pred['name']}_GE_uuid": req_pred
                        # for req_pred in req_preds
                    },
                }
                self.log(indy_proof_request)

                if revocation:
                    indy_proof_request["non_revoked"] = {"to": int(time.time())}

                proof_request_web_request = {
                    "presentation_request": {"indy": indy_proof_request},
                    "trace": exchange_tracing,
                }
                if not connectionless:
                    proof_request_web_request["connection_id"] = self.connection_id
                return proof_request_web_request


            else:
                raise Exception(f"Error invalid credential type: {self.cred_type}")

        else:
            raise Exception(f"Error invalid AIP level: {self.aip}")




async def main(args):
    diploma_agent = await create_agent_with_args(args, ident="diploma")

    try:
        log_status(
            "#1 Provision an agent and wallet, get back configuration details"
            + (
                f" (Wallet type: {diploma_agent.wallet_type})"
                if diploma_agent.wallet_type
                else ""
            )
        )
        agent = DiplomaAgent(
            "diploma.agent",
            diploma_agent.start_port,
            diploma_agent.start_port + 1,
            genesis_data=diploma_agent.genesis_txns,
            genesis_txn_list=diploma_agent.genesis_txn_list,
            no_auto=diploma_agent.no_auto,
            tails_server_base_url=diploma_agent.tails_server_base_url,
            revocation=diploma_agent.revocation,
            timing=diploma_agent.show_timing,
            multitenant=diploma_agent.multitenant,
            mediation=diploma_agent.mediation,
            wallet_type=diploma_agent.wallet_type,
            seed=diploma_agent.seed,
            aip=diploma_agent.aip,
            endorser_role=diploma_agent.endorser_role,
            anoncreds_legacy_revocation=diploma_agent.anoncreds_legacy_revocation,
        )

        diploma_schema_name = "diploma schema"
        diploma_schema_attrs = [
            "name",
            "date",
            "degree",
            "grade",
        ]
        if diploma_agent.cred_type == CRED_FORMAT_INDY:
            diploma_agent.public_did = True
            await diploma_agent.initialize(
                the_agent=agent,
                schema_name=diploma_schema_name,
                schema_attrs=diploma_schema_attrs,
                create_endorser_agent=(diploma_agent.endorser_role == "author")
                if diploma_agent.endorser_role
                else False,
            )
        elif diploma_agent.cred_type == CRED_FORMAT_JSON_LD:
            diploma_agent.public_did = True
            await diploma_agent.initialize(the_agent=agent)
        else:
            raise Exception("Invalid credential type:" + diploma_agent.cred_type)

        # generate an invitation for Alice
        await diploma_agent.generate_invitation(
            display_qr=False, display_invite=True, reuse_connections=diploma_agent.reuse_connections, wait=True
        )

        exchange_tracing = False
        options = (
            "    (1) Issue Credential\n"
            "    (2) Send Proof Request\n"
            "    (2a) Send *Connectionless* Proof Request (requires a Mobile client)\n"
            "    (3) Send Message\n"
            "    (4) Create New Invitation\n"
        )
        if diploma_agent.revocation:
            options += (
                "    (5) Revoke Credential\n"
                "    (6) Publish Revocations\n"
                "    (7) Rotate Revocation Registry\n"
                "    (8) List Revocation Registries\n"
            )
        if diploma_agent.endorser_role and diploma_agent.endorser_role == "author":
            options += "    (D) Set Endorser's DID\n"
        if diploma_agent.multitenant:
            options += "    (W) Create and/or Enable Wallet\n"
        options += "    (T) Toggle tracing on credential/proof exchange\n"
        options += "    (X) Exit?\n[1/2/3/4/{}{}T/X] ".format(
            "5/6/7/8/" if diploma_agent.revocation else "",
            "W/" if diploma_agent.multitenant else "",
        )
        async for option in prompt_loop(options):
            if option is not None:
                option = option.strip()

            if option is None or option in "xX":
                break

            elif option in "dD" and diploma_agent.endorser_role:
                endorser_did = await prompt("Enter Endorser's DID: ")
                await diploma_agent.agent.admin_POST(
                    f"/transactions/{diploma_agent.agent.connection_id}/set-endorser-info",
                    params={"endorser_did": endorser_did},
                )

            elif option in "wW" and diploma_agent.multitenant:
                target_wallet_name = await prompt("Enter wallet name: ")
                include_subwallet_webhook = await prompt(
                    "(Y/N) Create sub-wallet webhook target: "
                )
                if include_subwallet_webhook.lower() == "y":
                    created = await diploma_agent.agent.register_or_switch_wallet(
                        target_wallet_name,
                        webhook_port=diploma_agent.agent.get_new_webhook_port(),
                        public_did=True,
                        mediator_agent=diploma_agent.mediator_agent,
                        endorser_agent=diploma_agent.endorser_agent,
                        taa_accept=diploma_agent.taa_accept,
                    )
                else:
                    created = await diploma_agent.agent.register_or_switch_wallet(
                        target_wallet_name,
                        public_did=True,
                        mediator_agent=diploma_agent.mediator_agent,
                        endorser_agent=diploma_agent.endorser_agent,
                        cred_type=diploma_agent.cred_type,
                        taa_accept=diploma_agent.taa_accept,
                    )
                # create a schema and cred def for the new wallet
                # TODO check first in case we are switching between existing wallets
                if created:
                    # TODO this fails because the new wallet doesn't get a public DID
                    await diploma_agent.create_schema_and_cred_def(
                        schema_name=diploma_schema_name,
                        schema_attrs=diploma_schema_attrs,
                    )

            elif option in "tT":
                exchange_tracing = not exchange_tracing
                log_msg(
                    ">>> Credential/Proof Exchange Tracing is {}".format(
                        "ON" if exchange_tracing else "OFF"
                    )
                )

            elif option == "1":
                # JH TODO check if user has valid login
                log_status("attempting to proof degree")
                # await diploma_agent.check_proof_degree()
                if diploma_agent.aip == 10:

                    log_status("AIP 1.0 not maintained. possibly not supported")
                    proof_request_web_request = (
                        diploma_agent.agent.generate_proof_request_degree(
                            diploma_agent.aip,
                            diploma_agent.cred_type,
                            diploma_agent.revocation,
                            exchange_tracing,
                        )
                    )
                    await diploma_agent.agent.admin_POST(
                        "/present-proof/send-request", proof_request_web_request
                    )
                    pass

                elif diploma_agent.aip == 20:
                    if diploma_agent.cred_type == CRED_FORMAT_INDY:
                        proof_request_web_request = (
                            diploma_agent.agent.generate_proof_request_degree(
                                diploma_agent.aip,
                                diploma_agent.cred_type,
                                diploma_agent.revocation,
                                exchange_tracing,
                            )
                        )

                    elif diploma_agent.cred_type == CRED_FORMAT_JSON_LD:
                        proof_request_web_request = (
                            diploma_agent.agent.generate_proof_request_degree(
                                diploma_agent.aip,
                                diploma_agent.cred_type,
                                diploma_agent.revocation,
                                exchange_tracing,
                            )
                        )

                    else:
                        raise Exception(
                            "Error invalid credential type:" + diploma_agent.cred_type
                        )

                    reply = await agent.admin_POST(
                        "/present-proof-2.0/send-request", proof_request_web_request
                    )

                    log_status(f"request reply: {reply}")

                else:
                    raise Exception(f"Error invalid AIP level: {diploma_agent.aip}")

                log_status("proof degree finished")



            elif option == "2":
                log_status("#20 Request proof of degree from alice")
                if diploma_agent.aip == 10:

                    log_status("AIP 1.0 not maintained. possibly not supported")
                    proof_request_web_request = (
                        diploma_agent.agent.generate_proof_request_web_request(
                            diploma_agent.aip,
                            diploma_agent.cred_type,
                            diploma_agent.revocation,
                            exchange_tracing,
                        )
                    )
                    await diploma_agent.agent.admin_POST(
                        "/present-proof/send-request", proof_request_web_request
                    )
                    pass

                elif diploma_agent.aip == 20:
                    if diploma_agent.cred_type == CRED_FORMAT_INDY:
                        proof_request_web_request = (
                            diploma_agent.agent.generate_proof_request_web_request(
                                diploma_agent.aip,
                                diploma_agent.cred_type,
                                diploma_agent.revocation,
                                exchange_tracing,
                            )
                        )

                    elif diploma_agent.cred_type == CRED_FORMAT_JSON_LD:
                        proof_request_web_request = (
                            diploma_agent.agent.generate_proof_request_web_request(
                                diploma_agent.aip,
                                diploma_agent.cred_type,
                                diploma_agent.revocation,
                                exchange_tracing,
                            )
                        )

                    else:
                        raise Exception(
                            "Error invalid credential type:" + diploma_agent.cred_type
                        )

                    await agent.admin_POST(
                        "/present-proof-2.0/send-request", proof_request_web_request
                    )

                else:
                    raise Exception(f"Error invalid AIP level: {diploma_agent.aip}")

            elif option == "2a":
                log_status("#20 Request * Connectionless * proof of degree from alice")
                if diploma_agent.aip == 10:
                    proof_request_web_request = (
                        diploma_agent.agent.generate_proof_request_web_request(
                            diploma_agent.aip,
                            diploma_agent.cred_type,
                            diploma_agent.revocation,
                            exchange_tracing,
                            connectionless=True,
                        )
                    )
                    proof_request = await diploma_agent.agent.admin_POST(
                        "/present-proof/create-request", proof_request_web_request
                    )
                    pres_req_id = proof_request["presentation_exchange_id"]
                    url = (
                                  os.getenv("WEBHOOK_TARGET")
                                  or (
                                          "http://"
                                          + os.getenv("DOCKERHOST").replace(
                                      "{PORT}", str(diploma_agent.agent.admin_port + 1)
                                  )
                                          + "/webhooks"
                                  )
                          ) + f"/pres_req/{pres_req_id}/"
                    log_msg(f"Proof request url: {url}")
                    qr = QRCode(border=1)
                    qr.add_data(url)
                    log_msg(
                        "Scan the following QR code to accept the proof request from a mobile agent."
                    )
                    qr.print_ascii(invert=True)

                elif diploma_agent.aip == 20:
                    if diploma_agent.cred_type == CRED_FORMAT_INDY:
                        proof_request_web_request = (
                            diploma_agent.agent.generate_proof_request_web_request(
                                diploma_agent.aip,
                                diploma_agent.cred_type,
                                diploma_agent.revocation,
                                exchange_tracing,
                                connectionless=True,
                            )
                        )
                    elif diploma_agent.cred_type == CRED_FORMAT_JSON_LD:
                        proof_request_web_request = (
                            diploma_agent.agent.generate_proof_request_web_request(
                                diploma_agent.aip,
                                diploma_agent.cred_type,
                                diploma_agent.revocation,
                                exchange_tracing,
                                connectionless=True,
                            )
                        )
                    else:
                        raise Exception(
                            "Error invalid credential type:" + diploma_agent.cred_type
                        )

                    proof_request = await diploma_agent.agent.admin_POST(
                        "/present-proof-2.0/create-request", proof_request_web_request
                    )
                    pres_req_id = proof_request["pres_ex_id"]
                    url = (
                            "http://"
                            + os.getenv("DOCKERHOST").replace(
                        "{PORT}", str(diploma_agent.agent.admin_port + 1)
                    )
                            + "/webhooks/pres_req/"
                            + pres_req_id
                            + "/"
                    )
                    log_msg(f"Proof request url: {url}")
                    qr = QRCode(border=1)
                    qr.add_data(url)
                    log_msg(
                        "Scan the following QR code to accept the proof request from a mobile agent."
                    )
                    qr.print_ascii(invert=True)
                else:
                    raise Exception(f"Error invalid AIP level: {diploma_agent.aip}")

            elif option == "3":
                msg = await prompt("Enter message: ")
                await diploma_agent.agent.admin_POST(
                    f"/connections/{diploma_agent.agent.connection_id}/send-message",
                    {"content": msg},
                )

            elif option == "4":
                log_msg(
                    "Creating a new invitation, please receive "
                    "and accept this invitation using Alice agent"
                )
                await diploma_agent.generate_invitation(
                    display_invite=True,
                    display_qr=False,
                    reuse_connections=diploma_agent.reuse_connections,
                    wait=True,
                )

            elif option == "5" and diploma_agent.revocation:
                rev_reg_id = (await prompt("Enter revocation registry ID: ")).strip()
                cred_rev_id = (await prompt("Enter credential revocation ID: ")).strip()
                publish = (
                              await prompt("Publish now? [Y/N]: ", default="N")
                          ).strip() in "yY"
                try:
                    await diploma_agent.agent.admin_POST(
                        "/revocation/revoke",
                        {
                            "rev_reg_id": rev_reg_id,
                            "cred_rev_id": cred_rev_id,
                            "publish": publish,
                            "connection_id": diploma_agent.agent.connection_id,
                            # leave out thread_id, let aca-py generate
                            # "thread_id": "12345678-4444-4444-4444-123456789012",
                            "comment": "Revocation reason goes here ...",
                        },
                    )
                except ClientError:
                    pass

            elif option == "6" and diploma_agent.revocation:
                try:
                    resp = await diploma_agent.agent.admin_POST(
                        "/revocation/publish-revocations", {}
                    )
                    diploma_agent.agent.log(
                        "Published revocations for {} revocation registr{} {}".format(
                            len(resp["rrid2crid"]),
                            "y" if len(resp["rrid2crid"]) == 1 else "ies",
                            json.dumps([k for k in resp["rrid2crid"]], indent=4),
                        )
                    )
                except ClientError:
                    pass
            elif option == "7" and diploma_agent.revocation:
                try:
                    resp = await diploma_agent.agent.admin_POST(
                        f"/revocation/active-registry/{diploma_agent.cred_def_id}/rotate",
                        {},
                    )
                    diploma_agent.agent.log(
                        "Rotated registries for {}. Decommissioned Registries: {}".format(
                            diploma_agent.cred_def_id,
                            json.dumps([r for r in resp["rev_reg_ids"]], indent=4),
                        )
                    )
                except ClientError:
                    pass
            elif option == "8" and diploma_agent.revocation:
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
                    resp = await diploma_agent.agent.admin_GET(
                        "/revocation/registries/created",
                        params={"state": state},
                    )
                    diploma_agent.agent.log(
                        "Registries (state = '{}'): {}".format(
                            state,
                            json.dumps([r for r in resp["rev_reg_ids"]], indent=4),
                        )
                    )
                except ClientError:
                    pass

        if diploma_agent.show_timing:
            timing = await diploma_agent.agent.fetch_timing()
            if timing:
                for line in diploma_agent.agent.format_timing(timing):
                    log_msg(line)

    finally:
        terminated = await diploma_agent.terminate()

    await asyncio.sleep(0.1)

    if not terminated:
        os._exit(1)


async def offer_credential(diploma_agent,exchange_tracing):
    log_status("#13 Issue credential offer to X")
    if diploma_agent.aip == 10:
        log_status("AIP 1.0 not maintained. possibly not supported")
        offer_request = diploma_agent.agent.generate_credential_offer(
            diploma_agent.aip, None, diploma_agent.cred_def_id, exchange_tracing
        )
        await diploma_agent.agent.admin_POST(
            "/issue-credential/send-offer", offer_request
        )

    elif diploma_agent.aip == 20:
        if diploma_agent.cred_type == CRED_FORMAT_INDY:
            offer_request = diploma_agent.agent.generate_credential_offer(
                diploma_agent.aip,
                diploma_agent.cred_type,
                diploma_agent.cred_def_id,
                exchange_tracing,
            )

        elif diploma_agent.cred_type == CRED_FORMAT_JSON_LD:
            offer_request = diploma_agent.agent.generate_credential_offer(
                diploma_agent.aip,
                diploma_agent.cred_type,
                None,
                exchange_tracing,
            )

        else:
            raise Exception(
                f"Error invalid credential type: {diploma_agent.cred_type}"
            )

        await diploma_agent.agent.admin_POST(
            "/issue-credential-2.0/send-offer", offer_request
        )

    else:
        raise Exception(f"Error invalid AIP level: {diploma_agent.aip}")

if __name__ == "__main__":
    parser = arg_parser(ident="diploma", port=8070)
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
                "Faber(diploma) remote debugging to "
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
