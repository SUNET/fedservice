import os

import pytest
import responses
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.server.oidc.token import Token
from idpyoidc.server.oidc.userinfo import UserInfo
from idpyoidc.util import rndstr

from fedservice.appserver.oidc.authorization import Authorization
from fedservice.appserver.oidc.registration import Registration
from fedservice.defaults import DEFAULT_OIDC_FED_SERVICES
from fedservice.defaults import federation_services
from fedservice.entity import get_verified_trust_chains
from . import create_trust_chain_messages
from . import CRYPT_CONFIG
from .build_federation import build_federation

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.join(BASE_PATH, "base_data")

COOKIE_KEYDEFS = [
    {"type": "oct", "kid": "sig", "use": ["sig"]},
    {"type": "oct", "kid": "enc", "use": ["enc"]}
]

TA_ID = "https://ta.example.org"
RP_ID = "https://rp.example.org"
OP_ID = "https://op.example.org"
IM_ID = "https://im.example.org"

TA_ENDPOINTS = ["entity_configuration", "fetch", "metadata_verification"]

RESPONSE_TYPES_SUPPORTED = [
    ["code"],
    ["id_token"],
    ["code", "id_token"],
    ["none"],
]

SESSION_PARAMS = {"encrypter": CRYPT_CONFIG}

RP_SERVICES = federation_services("entity_configuration", "entity_statement")
RP_SERVICES.update(DEFAULT_OIDC_FED_SERVICES)

OP_SERVICES = federation_services("entity_configuration", "entity_statement")
OP_SERVICES.update(DEFAULT_OIDC_FED_SERVICES)

FEDERATION_CONFIG = {
    TA_ID: {
        "entity_type": "trust_anchor",
        "subordinates": [IM_ID, OP_ID],
        "kwargs": {
            "preference": {
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.org",
                "contacts": "operations@ta.example.org"
            },
            "endpoints": ["entity_configuration", "list", "fetch", "resolve"],
        }
    },
    RP_ID: {
        "entity_type": "openid_relying_party",
        "trust_anchors": [TA_ID],
        "services": RP_SERVICES,
        "kwargs": {
            "authority_hints": [IM_ID],
            "entity_type_config": {
                "keys": {"key_defs": DEFAULT_KEY_DEFS},
                "client_id": RP_ID,
                "client_secret": "a longesh password",
                "authorization_request_endpoints": [
                    "authorization_endpoint", "pushed_authorization_request_endpoint"
                ],
                "redirect_uris": ["https://rp.example.com/cli/authz_cb"],
                "preference": {
                    "grant_types": ["authorization_code", "implicit", "refresh_token"],
                    "id_token_signed_response_alg": "ES256",
                    "token_endpoint_auth_method": "client_secret_basic",
                    "token_endpoint_auth_signing_alg": "ES256",
                    "client_registration_types": ["automatic"],
                    "request_parameter_supported": True
                }
            }
        }
    },
    OP_ID: {
        "entity_type": "openid_provider",
        "trust_anchors": [TA_ID],
        "kwargs": {
            "authority_hints": [TA_ID],
            "services": OP_SERVICES,
            "entity_type_config": {
                "keys": {"key_defs": DEFAULT_KEY_DEFS},
                "preference": {
                    "request_authentication_methods_supported": {
                        "authorization_endpoint": [
                            "request_object"
                        ],
                        "pushed_authorization_request_endpoint": [
                            "private_key_jwt"
                        ]
                    },
                    "subject_types_supported": ["public", "pairwise", "ephemeral"],
                    "grant_types_supported": [
                        "authorization_code",
                        "implicit",
                        "urn:ietf:params:oauth:grant-type:jwt-bearer",
                        "refresh_token",
                    ]
                },
                "token_handler_args": {
                    "jwks_def": {
                        "private_path": "private/token_jwks.json",
                        "read_only": False,
                        "key_defs": [
                            {"type": "oct", "bytes": "24", "use": ["enc"],
                             "kid": "code"}],
                    },
                    "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
                    "token": {
                        "class": "idpyoidc.server.token.jwt_token.JWTToken",
                        "kwargs": {
                            "lifetime": 3600,
                            "add_claims_by_scope": True,
                        },
                    },
                    "id_token": {
                        "class": "idpyoidc.server.token.id_token.IDToken",
                        "kwargs": {
                            "base_claims": {
                                "email": {"essential": True},
                                "email_verified": {"essential": True},
                            }
                        }
                    }
                },
                "key_conf": {"key_defs": DEFAULT_KEY_DEFS},
                "endpoint": {
                    "authorization": {
                        "path": "authorization",
                        "class": "fedservice.appserver.oidc.authorization.Authorization",
                        "kwargs": {
                            "response_types_supported": [" ".join(x) for x in
                                                         RESPONSE_TYPES_SUPPORTED],
                            "response_modes_supported": ["query", "fragment",
                                                         "form_post"],
                            "claim_types_supported": [
                                "normal",
                                "aggregated",
                                "distributed",
                            ],
                            "claims_parameter_supported": True,
                            "request_parameter_supported": True,
                            "request_uri_parameter_supported": True,
                            "client_registration_types_supported": ["automatic",
                                                                    "explicit"]
                        },
                    },
                    "registration": {
                        "path": "registration",
                        "class": "fedservice.appserver.oidc.registration.Registration",
                        "kwargs": {}
                    },
                    "token": {
                        "path": "token",
                        "class": Token,
                        "kwargs": {
                            "client_authn_method": [
                                "client_secret_post",
                                "client_secret_basic",
                                "client_secret_jwt",
                                "private_key_jwt",
                            ]
                        },
                    },
                    "userinfo": {
                        "path": "userinfo",
                        "class": UserInfo,
                        "kwargs": {}
                    },
                },
                "template_dir": "template",
                "session_params": SESSION_PARAMS,
            }
        },
    },
    IM_ID: {
        "entity_type": "federation_entity",
        "trust_anchors": [TA_ID],
        "subordinates": [RP_ID],
        "kwargs": {
            "authority_hints": [TA_ID],
        }
    }
}


class TestAutomatic(object):

    @pytest.fixture(autouse=True)
    def create_federation(self):
        #              TA
        #          +---|---+
        #          |       |
        #          IM      OP
        #          |
        #          RP

        federation = build_federation(FEDERATION_CONFIG)
        self.ta = federation[TA_ID]
        self.rp = federation[RP_ID]
        self.op = federation[OP_ID]
        self.im = federation[IM_ID]

    def test_automatic_registration(self):
        # No clients registered with the OP at the beginning
        assert len(self.op["openid_provider"].get_context().cdb.keys()) == 0

        ####################################################
        # [1] Let the RP gather some provider info

        # Point the RP to the OP
        self.rp["openid_relying_party"].get_context().issuer = self.op.entity_id

        # Create the URLs and messages that will be involved in this process
        _msgs = create_trust_chain_messages(self.op, self.ta)

        # add the jwks_uri
        _jwks_uri = self.op["openid_provider"].get_context().get_preference("jwks_uri")
        if _jwks_uri:
            _msgs[_jwks_uri] = self.op["openid_provider"].keyjar.export_jwks_as_json()

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/entity-statement+jwt"},
                         status=200)

            _trust_chains = get_verified_trust_chains(self.rp,
                                                      self.op["federation_entity"].entity_id)

        self.rp["openid_relying_party"].context.server_metadata = _trust_chains[0].metadata
        self.rp["federation_entity"].client.context.server_metadata = _trust_chains[0].metadata

        _context = self.rp["openid_relying_party"].get_context()

        # automatic registration == not explict registration
        # _context.map_supported_to_preferred(info=_trust_chains[0].metadata["openid_relying_party"])

        _auth_service = self.rp["openid_relying_party"].get_service("authorization")
        state = rndstr()
        authn_request = _auth_service.construct(request_args={"response_type": "code", "state": state})

        # ------------------------------
        # <<<<<< On the OPs side >>>>>>>

        _msgs = create_trust_chain_messages(self.rp, self.im, self.ta)
        # add the jwks_uri
        _jwks_uri = self.rp["openid_relying_party"].get_context().get_preference("jwks_uri")
        if _jwks_uri:
            _msgs[_jwks_uri] = self.rp["openid_relying_party"].keyjar.export_jwks_as_json()

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            # The OP handles the authorization request
            authz_endpoint = self.op["openid_provider"].get_endpoint("authorization")
            req = authz_endpoint.parse_request(authn_request)

        assert "response_type" in req

        # Assert that the client's entity_id has been registered as a client
        assert self.rp.entity_id in self.op["openid_provider"].get_context().cdb
        # Check that the RP's keys are reflected in the OP's keyjar
        assert self.rp.entity_id in self.op["openid_provider"].keyjar
        # There are three RP keys. One EC, one RSA and one OCT
        rp_keyjar = self.rp["openid_relying_party"].keyjar
        op_keyjar = self.op["openid_provider"].keyjar
        for key_type in ["EC", "RSA", "OCT"]:
            for key in rp_keyjar.get_signing_key(key_type=key_type):
                vk = op_keyjar.get_verify_key(key_type=key_type, kid=key.kid, issuer_id=self.rp.entity_id)
                assert vk