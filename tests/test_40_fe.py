import json
import os

import pytest
from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import init_key_jar

from fedservice.utils import make_federation_combo

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

SUB_KEYJAR = init_key_jar(key_defs=KEYDEFS)
BASE_PATH = os.path.abspath(os.path.dirname(__file__))

jwks = open(os.path.join(BASE_PATH, 'base_data', 'feide.no', 'feide.no', 'jwks.json')).read()
ANCHOR = {'https://feide.no': json.loads(jwks)}

OPPONENT_ID = "https://example.org"
TENNANT_ID = "https://example.org/tennant1"
ENTITY_ID = "https://entity.example.org"
CHILD_ID = "https://op.example.com"
ISSUER = "https://example.org/adm1"

TMI_ID = "https://tmi.example.org"
SIRTIFI_TRUST_MARK_ID = "https://refeds.org/sirtfi"


class TestFederationEntity(object):

    @pytest.fixture(autouse=True)
    def server_setup(self):
        self.entity = make_federation_combo(
            ENTITY_ID,
            preference={
                "organization_name": "The leaf operator",
                "homepage_uri": "https://leaf.example.com",
                "contacts": "operations@leaf.example.com"
            },
            key_config={"uri_path": "static/fed_jwks.json", "key_defs": KEYDEFS},
            authority_hints=['https://ntnu.no'],
            endpoints=["entity_configuration", "fetch", "list", "resolve"],
            trust_mark_entity={
                "class": "fedservice.trust_mark_entity.entity.TrustMarkEntity",
                "kwargs": {
                    "trust_mark_specification": {
                        "https://refeds.org/sirtfi": {
                            "lifetime": 2592000
                        }
                    },
                    "trust_mark_db": {
                        "class": "fedservice.trust_mark_entity.FileDB",
                        "kwargs": {
                            "https://refeds.org/sirtfi": "sirtfi",
                        }
                    },
                    "endpoint": {
                        "trust_mark": {
                            "path": "trust_mark",
                            "class": "fedservice.trust_mark_entity.server.trust_mark.TrustMark",
                            "kwargs": {
                                "client_authn_method": [
                                    "private_key_jwt"
                                ],
                                "auth_signing_alg_values": [
                                    "ES256"
                                ]
                            }
                        },
                        "trust_mark_list": {
                            "path": "trust_mark_list",
                            "class": "fedservice.trust_mark_entity.server.trust_mark_list.TrustMarkList",
                            "kwargs": {}
                        },
                        "trust_mark_status": {
                            "path": "trust_mark_status",
                            "class": "fedservice.trust_mark_entity.server.trust_mark_status.TrustMarkStatus",
                            "kwargs": {}
                        }
                    }
                }
            }
        )

        self.entity.server.subordinate = {
            'https://op.example.com': {
                "jwks": {"keys": SUB_KEYJAR.export_jwks()},
                "metadata_policy": {
                    "openid_provider": {
                        "organization_name": {"value": "NTNU"}
                    }
                }
            }
        }

    def test_client(self):
        assert self.entity

        _serv = self.entity.client.get_service('entity_configuration')
        _res = _serv.get_request_parameters(request_args={"entity_id": OPPONENT_ID})
        assert _res == {
            'method': 'GET',
            'url': 'https://example.org/.well-known/openid-federation'
        }
        _res = _serv.get_request_parameters(request_args={"entity_id": TENNANT_ID}, tenant=True)
        assert _res == {
            'method': 'GET',
            'url': 'https://example.org/tennant1/.well-known/openid-federation'
        }

    def test_server(self):
        _endpoint = self.entity.server.get_endpoint('entity_configuration')
        _req = _endpoint.parse_request({})
        _resp_args = _endpoint.process_request(_req)
        _jwt = factory(_resp_args['response'])
        payload = _jwt.jwt.payload()
        assert set(payload.keys()) == {'exp', 'jwks', 'sub', 'iat', 'metadata', 'iss', 'authority_hints'}
        assert payload["iss"] == payload["sub"]
        assert set(payload['metadata'].keys()) == {'federation_entity'}
        # Full set of endpoints
        assert set(payload['metadata']['federation_entity'].keys()) == {'contacts',
                                                                        'federation_fetch_endpoint',
                                                                        'federation_list_endpoint',
                                                                        'federation_resolve_endpoint',
                                                                        'federation_trust_mark_endpoint',
                                                                        'federation_trust_mark_list_endpoint',
                                                                        'federation_trust_mark_status_endpoint',
                                                                        'federation_trust_mark_endpoint_auth_methods',
                                                                        'federation_trust_mark_list_endpoint_auth_methods',
                                                                        'federation_trust_mark_status_endpoint_auth_methods',
                                                                        'homepage_uri',
                                                                        'organization_name'
                                                                        }

    def test_fetch(self):
        _endpoint = self.entity.server.get_endpoint('fetch')
        _req = _endpoint.parse_request({'iss': ENTITY_ID, 'sub': CHILD_ID})
        _resp_args = _endpoint.process_request(_req)
        _jwt = factory(_resp_args['response_msg'])
        payload = _jwt.jwt.payload()
        assert set(payload.keys()) == {'exp', 'jwks', 'sub', 'iat', 'metadata_policy', 'iss'}
        assert payload["iss"] == ENTITY_ID
        assert payload["sub"] == CHILD_ID
        assert set(payload['metadata_policy'].keys()) == {'openid_provider'}
        assert set(payload['metadata_policy']['openid_provider'].keys()) == {'organization_name'}

    def test_list(self):
        _endpoint = self.entity.server.get_endpoint('list')
        _req = _endpoint.parse_request({})
        _resp_args = _endpoint.process_request(_req)
        assert _resp_args['response_msg'] == f'["{CHILD_ID}"]'
