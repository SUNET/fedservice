import os

import pytest
import responses
from cryptojwt.jws.jws import factory
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS

from fedservice.entity.function import collect_trust_chains
from tests import create_trust_chain_messages
from tests import CRYPT_CONFIG
from tests.build_federation import build_federation

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.join(BASE_PATH, "base_data")

TA_ID = "https://ta.example.org"
OP_ID = "https://op.example.org"
RP_ID = "https://rp.example.org"

SESSION_PARAMS = {"encrypter": CRYPT_CONFIG}

TA_ENDPOINTS = {
    "entity_configuration": {
        "path": ".well-known/openid-federation",
        "class": 'fedservice.entity.server.entity_configuration.EntityConfiguration',
        "kwargs": {}
    },
    "signed_jwks": {
        'path': 'signed_jwks',
        'class': 'fedservice.entity.server.signed_jwks.SignedJWKS',
        'kwargs': {}
    },
    "fetch": {
        "path": "fetch",
        "class": 'fedservice.entity.server.fetch.Fetch',
        "kwargs": {}
    },
    "list": {
        "path": "list",
        "class": 'fedservice.entity.server.list.List',
        "kwargs": {}
    }
}

OP_FED_ENDPOINTS = {
    "entity_configuration": {
        "path": ".well-known/openid-federation",
        "class": 'fedservice.entity.server.entity_configuration.EntityConfiguration',
        "kwargs": {}
    },
    'oidc_authorization': {
        "path": "authn",
        'class': 'fedservice.appserver.oidc.authorization.Authorization',
        "kwargs": {}
    },
    'oidc_registration': {
        'class': 'fedservice.appserver.oidc.registration.Registration',
        'path': 'registration',
        'kwargs': {}
    },
    "signed_jwks": {
        'path': 'signed_jwks',
        'class': 'fedservice.entity.server.signed_jwks.SignedJWKS',
        'kwargs': {}
    }
}
OP_APP_ENDPOINTS = {
    "token": {
        "path": "token",
        "class": "idpyoidc.server.oidc.token.Token",
        "kwargs": {},
    },
    "userinfo": {
        "path": "user",
        "class": "idpyoidc.server.oidc.userinfo.UserInfo",
        "kwargs": {},
    }
}

# Outgoing service
OP_FED_SERVICES = {
    "entity_configuration": {
        "class": 'fedservice.entity.client.entity_configuration.EntityConfiguration',
        "kwargs": {}
    },
    "entity_statement": {
        "class": 'fedservice.entity.client.entity_statement.SubordinateStatement',
        "kwargs": {}
    },
    'signed_jwks': {
        "class": 'fedservice.entity.client.signed_jwks.SignedJWKS',
        "kwargs": {}
    }
}

OP_APP_SERVICES = {
    'signed_jwks': {
        "class": 'fedservice.entity.client.signed_jwks.SignedJWKS',
        "kwargs": {}
    }
}

# RP has access to the same services as the OP
RP_FED_SERVICES = OP_FED_SERVICES

# RP provides two endpoints
RP_FED_ENDPOINTS = {
    "entity_configuration": {
        "path": ".well-known/openid-federation",
        "class": 'fedservice.entity.server.entity_configuration.EntityConfiguration',
        "kwargs": {}
    },
    "signed_jwks": {
        'path': 'signed_jwks',
        'class': 'fedservice.entity.server.signed_jwks.SignedJWKS',
        'kwargs': {}
    }
}

FEDERATION_CONFIG = {
    TA_ID: {
        "federation_entity": {
            "subordinate": [OP_ID, RP_ID],
            "endpoint": TA_ENDPOINTS,
            "preference": {
                "organization_name": "The example federation operator",
                "organization_uri": "https://ta.example.org",
                "contacts": "operations@ta.example.org"
            },
        }
    },
    OP_ID: {
        "federation_entity": {
            "trust_anchors": [TA_ID],
            "endpoint": OP_FED_ENDPOINTS,
            "authority_hints": [TA_ID],
            'services': OP_FED_SERVICES
        },
        "openid_provider": {
            "keys": {"key_defs": DEFAULT_KEY_DEFS},
            "base_url": OP_ID,
            "server_type": 'oidc',
            "endpoint": OP_APP_ENDPOINTS,
            'services': OP_APP_SERVICES
        }
    },
    RP_ID: {
        "federation_entity": {
            "trust_anchors": [TA_ID],
            "authority_hints": [TA_ID],
            'endpoint': RP_FED_ENDPOINTS,
            "services": RP_FED_SERVICES,
        },
        "openid_relying_party": {
            "preference": {
                "organization_name": "The example federation RP operator",
                "organization_uri": "https://rp.example.com",
                "contacts": "operations@rp.example.com"
            }
        }
    }
}


class TestFederationStatement(object):

    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        #             TA
        #          +--|--+
        #          |     |
        #         OC    RP

        federation = build_federation(FEDERATION_CONFIG)
        self.ta = federation[TA_ID]
        self.op = federation[OP_ID]
        self.rp = federation[RP_ID]

    def test_1(self):
        # This simulates an OP fetching a signed_jwks from an RP

        # The messages that are used to build the trust chain from the RP to the TA
        _msg = create_trust_chain_messages(self.rp, self.ta)

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msg.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            # This to make the OP have the chain in its cache
            collect_trust_chains(self.op, RP_ID)

        _jwks_service = self.op['federation_entity'].get_service('signed_jwks')
        # Since the chain is already cached at the OP this will not demand any chain collection
        request = _jwks_service.get_request_parameters(request_args={"entity_id": self.rp.entity_id})
        assert request == {'url': 'https://rp.example.org/signed_jwks', 'method': 'GET'}

        # Now for what happens on the RP side.
        _jwks_endpoint = self.rp['federation_entity'].get_endpoint('signed_jwks')
        response = _jwks_endpoint.process_request({})
        assert list(response.keys()) == ["response_msg"]
        jws = factory(response["response_msg"])
        assert jws.jwt.headers['typ'] == 'application/jwk-set+jwt'

        # Sent back to the OP

        jwks_resp = _jwks_service.parse_response(response["response_msg"], "jwt", iss='https://rp.example.org')
        _jwks_service.update_service_context(jwks_resp)
        # Verify that the old keys has been inactivated
        # while the new ones has been added.

        keys = self.op['federation_entity'].context.keyjar.get_signing_key(issuer_id=jwks_resp['iss'])
        assert len(keys) == 4

        inactive = []
        for key in keys:
            if key.inactive_since:
                inactive.append(key.kid)
        assert len(inactive) == 2

        # Should test what happens if the RP rotates its keys

