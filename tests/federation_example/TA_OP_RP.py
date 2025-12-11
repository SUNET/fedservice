from idpyoidc.client.client_auth import CLIENT_AUTHN_METHOD
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.client.defaults import DEFAULT_OIDC_SERVICES

from fedservice.defaults import DEFAULT_OIDC_FED_SERVICES

TA_ID = "https://ta.example.org"
RP_ID = "https://rp.example.org"
OP_ID = "https://op.example.org"

FE_FUNCTIONS = {
    "trust_chain_collector": {
        "class": "fedservice.entity.function.trust_chain_collector.TrustChainCollector",
        "kwargs": {}
    },
    "verifier": {
        "class": "fedservice.entity.function.verifier.TrustChainVerifier",
        "kwargs": {}
    },
    "policy": {
        "class": "fedservice.entity.function.policy.TrustChainPolicy",
        "kwargs": {}
    },
    "trust_mark_verifier": {
        "class": "fedservice.entity.function.trust_mark_verifier.TrustMarkVerifier",
        "kwargs": {}
    }
}

OIDC_SERVICE = DEFAULT_OIDC_SERVICES.copy()
OIDC_SERVICE.update(DEFAULT_OIDC_FED_SERVICES)

FEDERATION_CONFIG = {
    TA_ID: {
        "federation_entity": {
            "subordinates": [RP_ID, OP_ID],
            "preference": {
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.org",
                "contacts": "operations@ta.example.org",
                "scopes_supported": ["openid", "profile"],
                "response_types_supported": ['id_token', 'code', 'code id_token']
            },
            "endpoint": ["entity_configuration", "list", "fetch", "resolve"],
        }
    },
    RP_ID: {
        "federation_entity": {
            "trust_anchors": [TA_ID],
            "services": ["oidc_registration", "entity_configuration", "entity_statement"],
            "authority_hints": [TA_ID],
        },
        "openid_relying_party": {
            "services": OIDC_SERVICE,
            "client_id": RP_ID,
            "client_secret": "a longesh password",
            "key_config": {"key_defs": DEFAULT_KEY_DEFS},
            "preference": {
                "grant_types": ["authorization_code", "implicit", "refresh_token"],
                "id_token_signed_response_alg": "ES256",
                "token_endpoint_auth_method": "client_secret_basic",
                "token_endpoint_auth_signing_alg": "ES256",
                "scopes_supported": ["openid", "profile"],
                "client_registration_types": ["explicit"]
            },
            'client_authn_methods': CLIENT_AUTHN_METHOD
        }
    },
    OP_ID: {
        "federation_entity": {
            "trust_anchors": [TA_ID],
            "authority_hints": [TA_ID],
            "endpoint": ["entity_configuration"]
        },
        "openid_provider": {
            "endpoint": {
                "oidc_authz": {
                    "path": "authz",
                    'class': 'fedservice.appserver.oidc.authorization.Authorization',
                    "kwargs": {}
                },
                "oidc_registration": {
                    "path": "registration",
                    'class': 'fedservice.appserver.oidc.registration.Registration',
                    "kwargs": {}
                },
                'token': {
                    'path': 'token',
                    'class': 'idpyoidc.server.oidc.token.Token',
                    'kwargs': {
                        'client_authn_method': [
                            'client_secret_post', 'client_secret_basic', 'client_secret_jwt', 'private_key_jwt']
                    }
                }
            }
        }
    }
}
