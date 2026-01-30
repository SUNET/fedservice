from idpyoidc.client.defaults import DEFAULT_KEY_DEFS

from fedservice.defaults import federation_services
from fedservice.defaults import OAUTH2_FED_ENDPOINTS
from fedservice.utils import make_federation_combo
from fedservice.utils import make_federation_entity
from tests import CRYPT_CONFIG
from tests import RESPONSE_TYPES_SUPPORTED
from tests import SESSION_PARAMS


ENTITY_TYPE_DEFAULTS = {
    'federation_entity': {
        "endpoint": ['entity_configuration'],
        'key_config': {"key_defs": DEFAULT_KEY_DEFS},
        'services': federation_services("entity_configuration", "entity_statement")
    },
    'openid_provider': {
        'class': "fedservice.appserver.ServerEntity",
        "metadata_schema": "fedservice.message.OPMetadata",
        "httpc_params": {"verify": False, "timeout": 1},
        "preference": {
            "subject_types_supported": ["public", "pairwise", "ephemeral"],
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
                },
            },
            "id_token": {
                "class": "idpyoidc.server.token.id_token.IDToken",
                "kwargs": {
                    "base_claims": {
                        "email": {"essential": True},
                        "email_verified": {"essential": True},
                    }
                },
            },
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
                    "response_types_supported": [" ".join(x) for x in RESPONSE_TYPES_SUPPORTED],
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
            },
            "userinfo": {
                "path": "userinfo",
                "class": "idpyoidc.server.oidc.userinfo.UserInfo",
                "kwargs": {}
            },
        },
        "template_dir": "template",
        "session_params": SESSION_PARAMS,
    },
    'openid_relying_party': {
        'class': "fedservice.appclient.ClientEntity",
        "key_config": {"key_defs": DEFAULT_KEY_DEFS},
        "preference": {
            "grant_types": ['authorization_code', 'implicit', 'refresh_token'],
            "id_token_signed_response_alg": "ES256",
            "token_endpoint_auth_method": "client_secret_basic"
        }
    },
    'oauth_authorization_server': {
        'class': "fedservice.appserver.ServerEntity",
        'key_config': {"key_defs": DEFAULT_KEY_DEFS},
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
                    "response_types_supported": [" ".join(x) for x in RESPONSE_TYPES_SUPPORTED],
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
    },
    'oauth_client': {
        'class': "fedservice.appclient.ClientEntity",
        "key_config": {"key_defs": DEFAULT_KEY_DEFS},
        "preference": {
            "grant_types": ['authorization_code', 'implicit', 'refresh_token'],
            "id_token_signed_response_alg": "ES256",
            "token_endpoint_auth_method": "client_secret_basic"
        },
        "server_type": "oauth2",
        "endpoint": OAUTH2_FED_ENDPOINTS
    }
}


def add_defaults(cnf):
    if "endpoint" not in cnf:
        cnf["endpoint"] = ['entity_configuration']
    if 'key_config' not in cnf:
        cnf['key_config'] = {"key_defs": DEFAULT_KEY_DEFS}
    if 'services' not in cnf:
        cnf['services'] = federation_services("entity_configuration", "entity_statement")
    return cnf


def main(entity_id: str, **kwargs):
    # if not entity_type_config:
    #     entity_type_config = OPENID_PROVIDER_CONFIG

    fe_args = {}
    at_args = {}
    for attr, val in kwargs.items():
        if attr in ENTITY_TYPE_DEFAULTS:
            _cpy = ENTITY_TYPE_DEFAULTS[attr].copy()
            if attr == "federation_entity":
                fe_args = _cpy
                fe_args.update(val)
                # remove now, will be added later
                for key in ['subordinate', 'trust_anchors']:
                    if key in fe_args:
                        del fe_args[key]
            elif attr in ['oauth_client', 'openid_relying_party']:
                at_args[attr] = _cpy
                at_args[attr].update(val)
                at_args[attr]['redirect_uris'] = [f'{entity_id}/cli/authz_cb']
            elif attr in ['openid_provider', 'oauth_authorization_server']:
                at_args[attr] = _cpy
                at_args[attr].update(val)

    if at_args == {}:
        entity = make_federation_entity(
            entity_id,
            **fe_args,
        )
    else:
        at_args["federation_entity"] = fe_args
        entity = make_federation_combo(
            entity_id,
            entity_type=at_args
        )

    return entity
