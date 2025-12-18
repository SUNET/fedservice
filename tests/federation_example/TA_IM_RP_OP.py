import os

from idpyoidc.client.client_auth import CLIENT_AUTHN_METHOD
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.server.oidc.token import Token
from idpyoidc.server.oidc.userinfo import UserInfo

from fedservice.defaults import DEFAULT_OIDC_FED_SERVICES
from fedservice.defaults import federation_services

CRYPT_CONFIG = {
    "kwargs": {
        "keys": {
            "key_defs": [
                {"type": "OCT", "use": ["enc"], "kid": "password"},
                {"type": "OCT", "use": ["enc"], "kid": "salt"},
            ]
        },
        "iterations": 1,
    }
}

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
        'federation_entity': {
            "subordinates": [IM_ID, OP_ID],
            "preference": {
                "organization_name": "The example federation operator",
                "organization_uri": "https://ta.example.org",
                "contacts": "operations@ta.example.org"
            },
            "endpoint": ["entity_configuration", "list", "fetch", "resolve"],
        }
    },
    RP_ID: {
        'federation_entity': {
            "trust_anchors": [TA_ID],
            "services": RP_SERVICES,
            "authority_hints": [IM_ID],
        },
        "openid_relying_party": {
            "keys": {"key_defs": DEFAULT_KEY_DEFS},
            "client_id": RP_ID,
            "client_secret": "a longesh password",
            "authorization_request_endpoints": [
                "authorization_endpoint", "pushed_authorization_request_endpoint"
            ],
            "redirect_uris": ["https://rp.example.com/cli/authz_cb"],
            'client_authn_methods': CLIENT_AUTHN_METHOD,
            "preference": {
                "grant_types": ["authorization_code", "implicit", "refresh_token"],
                "id_token_signed_response_alg": "ES256",
                "token_endpoint_auth_method": "client_secret_basic",
                "token_endpoint_auth_signing_alg": "ES256",
                "client_registration_types": ["automatic"],
                "request_parameter_supported": True,
            }
        }
    },
    OP_ID: {
        'federation_entity': {
            "trust_anchors": [TA_ID],
            "authority_hints": [TA_ID],
            "services": OP_SERVICES,
        },
        "openid_provider": {
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
                        "response_types_supported": [" ".join(x) for x in RESPONSE_TYPES_SUPPORTED],
                        "response_modes_supported": ["query", "fragment", "form_post"],
                        "claim_types_supported": ["normal", "aggregated", "distributed", ],
                        "claims_parameter_supported": True,
                        "request_parameter_supported": True,
                        "request_uri_parameter_supported": True,
                        "client_registration_types_supported": ["automatic", "explicit"]
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
                "pushed_authorization": {
                    "path": "pushed_authorization",
                    "class": "fedservice.appserver.oauth2.pushed_authorization.PushedAuthorization",
                    "kwargs": {
                        "client_authn_method": [
                            "client_secret_post",
                            "client_secret_basic",
                            "client_secret_jwt",
                            "private_key_jwt"
                        ]
                    }
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
    IM_ID: {
        'federation_entity': {
            "trust_anchors": [TA_ID],
            "subordinates": [RP_ID],
            "authority_hints": [TA_ID],
            'endpoint': ['entity_configuration', 'fetch', 'list']
        }
    }
}
