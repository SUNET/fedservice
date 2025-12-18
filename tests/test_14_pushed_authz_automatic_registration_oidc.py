import os

import pytest
import responses
from idpyoidc.message.oauth2.device_authorization import AuthorizationRequest
from idpyoidc.util import rndstr

from fedservice.entity.function import get_verified_trust_chains
from . import create_trust_chain_messages
from .build_federation import build_federation

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.join(BASE_PATH, "base_data")

# TA_ID = "https://ta.example.org"
# OC_ID = "https://client.example.org"
# AS_ID = "https://as.example.org"
# IM_ID = "https://im.example.org"
# 
# SESSION_PARAMS = {"encrypter": CRYPT_CONFIG}
# 
# OC_SERVICES = federation_services("entity_configuration", "entity_statement")
# # OC_SERVICES.update(DEFAULT_OAUTH2_FED_SERVICES)
# 
# AS_SERVICES = federation_services("entity_configuration", "entity_statement")
# AS_SERVICES.update(DEFAULT_OAUTH2_FED_SERVICES)
# 
# AS_ENDPOINTS = federation_endpoints("entity_configuration", "fetch")
# 
# 
# FEDERATION_CONFIG = {
#     TA_ID: {
#         "entity_type": "trust_anchor",
#         "subordinates": [IM_ID, AS_ID],
#         "kwargs": {
#             "preference": {
#                 "organization_name": "The example federation operator",
#                 "organization_uri": "https://ta.example.org",
#                 "contacts": "operations@ta.example.org"
#             },
#             "endpoint": ["entity_configuration", "list", "fetch", "resolve"],
#         }
#     },
#     OC_ID: {
#         "entity_type": "oauth_client",
#         "trust_anchors": [TA_ID],
#         "services": OC_SERVICES,
#         "kwargs": {
#             "authority_hints": [IM_ID],
#             "services": COMBINED_DEFAULT_OAUTH2_SERVICES,
#             "entity_type_config": {
#                 # OAuth2 core keys
#                 "keys": {"key_defs": DEFAULT_KEY_DEFS},
#                 "base_url": OC_ID,
#                 "client_id": OC_ID,
#                 "client_secret": "a longeeesh password",
#                 "redirect_uris": ["https://rp.example.com/cli/authz_cb"],
#                 "preference": {
#                     "grant_types": ["authorization_code", "implicit", "refresh_token"],
#                     "id_token_signed_response_alg": "ES256",
#                     "token_endpoint_auth_method": "client_secret_basic",
#                     "token_endpoint_auth_signing_alg": "ES256",
#                     "client_registration_types": ["automatic"],
#                     "request_parameter_supported": True
#                 },
#                 "authorization_request_endpoints": [
#                     "authorization_endpoint", "pushed_authorization_request_endpoint"
#                 ],
#                 'client_authn_methods': CLIENT_AUTHN_METHOD
#             }
#         }
#     },
#     AS_ID: {
#         "entity_type": "oauth_authorization_server",
#         "trust_anchors": [TA_ID],
#         "key_conf": {"key_defs": DEFAULT_KEY_DEFS},
#         "services": AS_SERVICES,
#         "endpoint": AS_ENDPOINTS,
#         "kwargs": {
#             "authority_hints": [TA_ID],
#             "entity_type_config": {
#                 "issuer": AS_ID,
#                 "httpc_params": {"verify": False, "timeout": 1},
#                 "preference": {
#                     "request_authentication_methods_supported": {
#                         "authorization_endpoint": [
#                             "request_object"
#                         ],
#                         "pushed_authorization_request_endpoint": [
#                             "private_key_jwt"
#                         ]
#                     },
#                     "subject_types_supported": ["public", "pairwise", "ephemeral"],
#                     "grant_types_supported": [
#                         "authorization_code",
#                         "implicit",
#                         "urn:ietf:params:oauth:grant-type:jwt-bearer",
#                         "refresh_token",
#                     ]
#                 },
#                 "token_handler_args": {
#                     "jwks_def": {
#                         "private_path": "private/token_jwks.json",
#                         "read_only": False,
#                         "key_defs": [
#                             {"type": "oct", "bytes": "24", "use": ["enc"],
#                              "kid": "code"}],
#                     },
#                     "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
#                     "token": {
#                         "class": "idpyoidc.server.token.jwt_token.JWTToken",
#                         "kwargs": {
#                             "lifetime": 3600,
#                             "add_claims_by_scope": True,
#                         },
#                     },
#                     "id_token": {
#                         "class": "idpyoidc.server.token.id_token.IDToken",
#                         "kwargs": {
#                             "base_claims": {
#                                 "email": {"essential": True},
#                                 "email_verified": {"essential": True},
#                             }
#                         }
#                     }
#                 },
#                 "key_conf": {"key_defs": DEFAULT_KEY_DEFS},
#                 "endpoint": {
#                     "authorization": {
#                         "path": "authorization",
#                         "class": "fedservice.appserver.oauth2.authorization.Authorization",
#                         "kwargs": {
#                             "response_types_supported": [" ".join(x) for x in
#                                                          RESPONSE_TYPES_SUPPORTED],
#                             "response_modes_supported": ["query", "fragment",
#                                                          "form_post"],
#                             "claim_types_supported": [
#                                 "normal",
#                                 "aggregated",
#                                 "distributed",
#                             ],
#                             "claims_parameter_supported": True,
#                             "request_parameter_supported": True,
#                             "request_uri_parameter_supported": True,
#                             "client_registration_types_supported": ["automatic",
#                                                                     "explicit"]
#                         },
#                     },
#                     "registration": {
#                         "path": "registration",
#                         "class": "fedservice.appserver.oidc.registration.Registration",
#                         "kwargs": {}
#                     },
#                     "token": {
#                         "path": "token",
#                         "class": Token,
#                         "kwargs": {
#                             "client_authn_method": [
#                                 "client_secret_post",
#                                 "client_secret_basic",
#                                 "client_secret_jwt",
#                                 "private_key_jwt",
#                             ]
#                         }
#                     },
#                     "pushed_authorization": {
#                         "path": "pushed_authorization",
#                         "class": "fedservice.appserver.oauth2.pushed_authorization.PushedAuthorization",
#                         "kwargs": {
#                             "client_authn_method": [
#                                 "client_secret_post",
#                                 "client_secret_basic",
#                                 "client_secret_jwt",
#                                 "private_key_jwt"
#                             ]
#                         }
#                     }
#                 },
#                 "template_dir": "template",
#                 "session_params": SESSION_PARAMS,
#             }
#         },
#     },
#     IM_ID: {
#         "entity_type": "federation_entity",
#         "trust_anchors": [TA_ID],
#         "subordinates": [OC_ID],
#         "kwargs": {
#             "authority_hints": [TA_ID]
#         }
#     }
# }

from .federation_example import TA_IM_RP_OP


class TestAutomatic(object):

    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        #              TA
        #          +---|---+
        #          |       |
        #          IM     OAS
        #          |
        #          OC

        federation = build_federation(TA_IM_RP_OP.FEDERATION_CONFIG)
        self.ta = federation[TA_IM_RP_OP.TA_ID]
        self.rp = federation[TA_IM_RP_OP.RP_ID]
        self.op = federation[TA_IM_RP_OP.OP_ID]
        self.im = federation[TA_IM_RP_OP.IM_ID]

        self.entity_config_service = self.rp["federation_entity"].get_service("entity_configuration")
        self.entity_config_service.upstream_get("context").issuer = TA_IM_RP_OP.OP_ID
        self.registration_service = self.rp["federation_entity"].get_service("registration")

    def test_automatic_registration_pushed_authz(self):
        # No clients registered with the OP at the beginning
        assert len(self.op["openid_provider"].get_context().cdb.keys()) == 0

        ###########################################
        # [1] Let the RP gather some provider info

        # Point the RP to the OP
        self.rp['openid_relying_party'].get_context().issuer = self.op.entity_id

        # Create the URLs and messages that will be involved in this process
        _msgs = create_trust_chain_messages(self.op, self.ta)

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/entity-statement+jwt"},
                         status=200)

            _trust_chains = get_verified_trust_chains(self.rp,
                                                      self.op["federation_entity"].entity_id)

        _context = self.rp['openid_relying_party'].context
        _context.server_metadata = _trust_chains[0].metadata
        self.rp["federation_entity"].client.context.server_metadata = _trust_chains[0].metadata
        _context.provider_info = _context.server_metadata["openid_provider"]

        # create the authorization request

        request_args = AuthorizationRequest(response_type="code", state=rndstr(),
                                            client_id=self.rp["federation_entity"].entity_id)
        _auth_service = self.rp['openid_relying_party'].get_service("authorization")

        # There is a side effect here. The function is really badly named.
        # client_assertion and client_assertion_type are added to the request
        _headers = _auth_service.get_headers(request_args, http_method="POST", authn_method="private_key_jwt")
        _headers["Content-Type"] = "application/x-www-form-urlencoded"

        _body = request_args.to_urlencoded()

        # ------------------------------
        # <<<<<< On the AS's side >>>>>>>

        _msgs = create_trust_chain_messages(self.rp, self.im, self.ta)

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/entity-statement+jwt"},
                         status=200)

            # The OP handles the authorization request
            _pushed_authz_endpoint = self.op["openid_provider"].get_endpoint("pushed_authorization")
            req = _pushed_authz_endpoint.parse_request(_body)

        assert "response_type" in req

        # Assert that the client"s entity_id has been registered as a client
        assert self.rp.entity_id in self.op["openid_provider"].get_context().cdb
