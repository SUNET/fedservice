from typing import List
from typing import Optional

from idpyoidc.client.defaults import DEFAULT_KEY_DEFS

from fedservice.defaults import DEFAULT_FEDERATION_ENTITY_ENDPOINTS
from fedservice.utils import make_federation_combo
from tests import CRYPT_CONFIG
from tests import SESSION_PARAMS

TA_ENDPOINTS = DEFAULT_FEDERATION_ENTITY_ENDPOINTS.copy()

RESPONSE_TYPES_SUPPORTED = [
    ["code"],
    ["id_token"],
    ["code", "id_token"]
]


def main(entity_id: str,
         authority_hints: Optional[List[str]] = None,
         trust_anchors: Optional[dict] = None,
         preference: Optional[dict] = None,
         endpoint: Optional[list] = None,
         entity_type_config: Optional[dict] = None):
    if preference is None:
        preference = {
            "organization_name": "The RP",
            "homepage_uri": "https://rp.example.com",
            "contacts": "operations@rp.example.com"
        }
    if not entity_type_config:
        entity_type_config = {
            "issuer": entity_id,
            "metadata_schema": "fedservice.message.FedASConfigurationResponse",
            "server_type": "oauth2",
            "httpc_params": {"verify": False, "timeout": 1},
            "preference": {
                "grant_types_supported": [
                    "authorization_code",
                    "implicit",
                    "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "refresh_token",
                ],
            },
            "token_handler_args": {
                "jwks_def": {
                    "private_path": "private/token_jwks.json",
                    "read_only": False,
                    "key_defs": [
                        {"type": "oct", "bytes": "24", "use": ["enc"],
                         "kid": "code"}],
                },
                "code": {
                    "lifetime": 600,
                    "kwargs": {
                        "crypt_conf": CRYPT_CONFIG
                    }
                },
                "token": {
                    "class": "idpyoidc.server.token.jwt_token.JWTToken",
                    "kwargs": {
                        "lifetime": 3600,
                        "add_claims_by_scope": True,
                    },
                },
                "refresh": {
                    "class": "idpyoidc.server.token.jwt_token.JWTToken",
                    "kwargs": {
                        "lifetime": 3600,
                    }
                }
            },
            "endpoint": {
                "registration": {
                    "path": "registration",
                    "class": "fedservice.appserver.oidc.registration.Registration",
                    "kwargs": {"client_auth_method": None},
                },
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
                    },
                },
                "token": {
                    "path": "token",
                    "class": "idpyoidc.server.oidc.token.Token",
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

    entity = make_federation_combo(
        entity_id,
        preference=preference,
        authority_hints=authority_hints,
        endpoint=endpoint,
        trust_anchors=trust_anchors,
        httpc_params={
            "verify": False,
            "timeout": 14
        },
        entity_type={
            "oauth_authorization_server": {
                'class': "fedservice.appserver.ServerEntity",
                "key_conf": {"key_defs": DEFAULT_KEY_DEFS},
                'kwargs': {
                    'config': entity_type_config
                }
            }
        }
    )

    return entity
