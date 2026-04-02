import os

import pytest
import responses
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.server.oidc.token import Token
from idpyoidc.util import rndstr

from fedservice import get_payload
from fedservice.defaults import COMBINED_DEFAULT_OAUTH2_SERVICES
from fedservice.defaults import DEFAULT_OAUTH2_FED_SERVICES
from fedservice.defaults import federation_endpoints
from fedservice.defaults import federation_services
from fedservice.entity.function import get_verified_trust_chains
from . import create_trust_chain_messages
from . import CRYPT_CONFIG
from . import RESPONSE_TYPES_SUPPORTED
from .build_federation import build_federation

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.join(BASE_PATH, "base_data")

TA_ID = "https://ta.example.org"
OC_ID = "https://client.example.org"
AS_ID = "https://as.example.org"
IM_ID = "https://im.example.org"

SESSION_PARAMS = {"encrypter": CRYPT_CONFIG}

OC_SERVICES = federation_services("entity_configuration", "entity_statement")
# OC_SERVICES.update(DEFAULT_OAUTH2_FED_SERVICES)

AS_SERVICES = federation_services("entity_configuration", "entity_statement")
AS_SERVICES.update(DEFAULT_OAUTH2_FED_SERVICES)

AS_ENDPOINTS = federation_endpoints("entity_configuration", "fetch")

FEDERATION_CONFIG = {
    TA_ID: {
        "entity_type": "trust_anchor",
        "subordinates": [IM_ID, AS_ID],
        "kwargs": {
            "preference": {
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.org",
                "contacts": "operations@ta.example.org"
            },
            "endpoints": ["entity_configuration", "list", "fetch", "resolve"],
        }
    },
    OC_ID: {
        "entity_type": "oauth_client",
        "trust_anchors": [TA_ID],
        "services": OC_SERVICES,
        "kwargs": {
            "authority_hints": [IM_ID],
            "services": COMBINED_DEFAULT_OAUTH2_SERVICES,
            "entity_type_config": {
                # OAuth2 core keys
                "keys": {"key_defs": DEFAULT_KEY_DEFS},
                "base_url": OC_ID,
                "client_id": OC_ID,
                "client_secret": "a longeeesh password",
                "redirect_uris": ["https://rp.example.com/cli/authz_cb"],
                "preference": {
                    "grant_types": ["authorization_code", "implicit", "refresh_token"],
                    "id_token_signed_response_alg": "ES256",
                    "token_endpoint_auth_method": "client_secret_basic",
                    "token_endpoint_auth_signing_alg": "ES256",
                    "client_registration_types": ["automatic"],
                    "request_parameter_supported": True
                },
                "authorization_request_endpoints": [
                    "authorization_endpoint", "pushed_authorization_request_endpoint"
                ]
            }
        }
    },
    AS_ID: {
        "entity_type": "oauth_authorization_server",
        "trust_anchors": [TA_ID],
        "key_conf": {"key_defs": DEFAULT_KEY_DEFS},
        "services": AS_SERVICES,
        "endpoints": AS_ENDPOINTS,
        "kwargs": {
            "authority_hints": [TA_ID],
            "entity_type_config": {
                "issuer": AS_ID,
                "httpc_params": {"verify": False, "timeout": 1},
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
                        "class": "fedservice.appserver.oauth2.authorization.Authorization",
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
                        }
                    }
                },
                "template_dir": "template",
                "session_params": SESSION_PARAMS,
            }
        },
    },
    IM_ID: {
        "entity_type": "federation_entity",
        "trust_anchors": [TA_ID],
        "subordinates": [OC_ID],
        "kwargs": {
            "authority_hints": [TA_ID]
        }
    }
}


class TestAutomatic(object):

    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        #              TA
        #          +---|---+
        #          |       |
        #          IM     OAS
        #          |
        #          OC

        federation = build_federation(FEDERATION_CONFIG)
        self.ta = federation[TA_ID]
        self.oc = federation[OC_ID]
        self.oas = federation[AS_ID]
        self.im = federation[IM_ID]

        self.entity_config_service = self.oc["federation_entity"].get_service(
            "entity_configuration")
        self.entity_config_service.upstream_get("context").issuer = AS_ID
        self.registration_service = self.oc["federation_entity"].get_service("registration")

    def test_automatic_registration_new_client_id(self):
        # No clients registered with the OP at the beginning
        assert len(self.oas["oauth_authorization_server"].get_context().cdb.keys()) == 0

        ####################################################
        # [1] Let the RP gather some provider info discovery

        # Point the RP to the OP
        self.oc["oauth_client"].get_context().issuer = self.oas.entity_id

        # Create the URLs and messages that will be involved in this process
        _msgs = create_trust_chain_messages(self.oas, self.ta)

        # add the jwks_uri
        _jwks_uri = self.oas["oauth_authorization_server"].get_context().get_preference("jwks_uri")
        if _jwks_uri:
            _msgs[_jwks_uri] = self.oas["oauth_authorization_server"].keyjar.export_jwks_as_json()

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/entity-statement+jwt"},
                         status=200)

            _trust_chains = get_verified_trust_chains(self.oc,
                                                      self.oas["federation_entity"].entity_id)

        self.oc["oauth_client"].context.server_metadata = _trust_chains[0].metadata
        self.oc["federation_entity"].client.context.server_metadata = _trust_chains[0].metadata

        # create the authorization request

        _auth_service = self.oc["oauth_client"].get_service("authorization")
        authn_request = _auth_service.construct(request_args={"response_type": "code",
                                                              "state": rndstr()})

        # ------------------------------
        # <<<<<< On the AS's side >>>>>>>

        _msgs = create_trust_chain_messages(self.oc, self.im, self.ta)
        # add the jwks_uri
        _jwks_uri = self.oc["oauth_client"].get_context().get_preference("jwks_uri")
        if _jwks_uri:
            _msgs[_jwks_uri] = self.oc["oauth_client"].keyjar.export_jwks_as_json()

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/entity-statement+jwt"},
                         status=200)

            # The OP handles the authorization request
            _authz_endpoint = self.oas["oauth_authorization_server"].get_endpoint("authorization")
            req = _authz_endpoint.parse_request(authn_request)

        assert "response_type" in req

        # Assert that the client"s entity_id has been registered as a client
        assert self.oc.entity_id in self.oas["oauth_authorization_server"].get_context().cdb

    def test_authz_request_with_trust_chain(self):
        # No clients registered with the OP at the beginning
        assert len(self.oas["oauth_authorization_server"].get_context().cdb.keys()) == 0

        ####################################################
        # [1] Let the RP gather some provider info discovery

        # Point the RP to the OP
        self.oc["oauth_client"].get_context().issuer = self.oas.entity_id

        # Create the URLs and messages that will be involved in this process AS -> TA
        _msgs = create_trust_chain_messages(self.oas, self.ta)

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/entity-statement+jwt"},
                         status=200)

            # The client collects trust chain from the AS
            _trust_chains = get_verified_trust_chains(self.oc, self.oas["federation_entity"].entity_id)

        # one would assume this
        # self.oc["oauth_client"].context.server_metadata = _trust_chains[0].metadata['oauth_authorization_server']
        # But NO this is what is expected
        self.oc["oauth_client"].context.server_metadata = _trust_chains[0].metadata
        self.oc["federation_entity"].client.context.server_metadata = _trust_chains[0].metadata

        # create trust chain client->TA. This will later be added to the Authz request
        _msgs = create_trust_chain_messages(self.oc, self.im, self.ta)
        trust_chain = [_msgs[es] for es in ['https://client.example.org/.well-known/openid-federation',
                                            'https://im.example.org/fetch',
                                            'https://ta.example.org/fetch']]

        # create authorization request with request object
        _auth_service = self.oc["oauth_client"].get_service("authorization")
        authn_request = _auth_service.construct(
            request_args={"response_type": "code", "state": rndstr(), "trust_chain": trust_chain,
                          "redirect_uri": self.oc["oauth_client"].context.claims.get_preference("redirect_uris")[0]})

        assert "request" in authn_request
        _req_args = get_payload(authn_request["request"])
        assert set(_req_args.keys()) == {'aud',
                                         'client_id',
                                         'exp',
                                         'iat',
                                         'iss',
                                         'jti',
                                         'redirect_uri',
                                         'response_type',
                                         'state',
                                         'trust_chain'}

        # ------------------------------
        # <<<<<< On the AS's side >>>>>>>

        # _msgs = create_trust_chain_messages(self.oc, self.im, self.ta)
        _msgs = {}
        # add the jwks_uri
        _jwks_uri = self.oc["oauth_client"].get_context().get_preference("jwks_uri")
        if _jwks_uri:
            _msgs[_jwks_uri] = self.oc["oauth_client"].keyjar.export_jwks_as_json()

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/entity-statement+jwt"},
                         status=200)

            # The OP handles the authorization request
            _authz_endpoint = self.oas["oauth_authorization_server"].get_endpoint("authorization")
            try:
                req = _authz_endpoint.parse_request(authn_request)
            except Exception as err:
                print(err)

        assert "response_type" in req
