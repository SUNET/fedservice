import os
from urllib.parse import urlparse

from cryptojwt import JWT
from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import build_keyjar
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
import pytest
import responses

from fedservice.message import TrustMarkRequest
from tests import create_trust_chain_messages
from tests.build_federation import build_federation

TRUST_MARK_OWNERS_KEYS = build_keyjar(DEFAULT_KEY_DEFS)
TM_OWNERS_ID = "https://tm_owner.example.org"

SIRTIFI_TRUST_MARK_ID = "https://refeds.org/sirtfi"

BASE_PATH = os.path.abspath(os.path.dirname(__file__))

TA_ID = "https://ta.example.org"
TMI_ID = "https://tmi.example.org"
FE_ID = "https://fe.example.org"

FEDERATION_CONFIG = {
    TA_ID: {
        "entity_type": "trust_anchor",
        "subordinates": [TMI_ID, FE_ID],
        "kwargs": {
            "preference": {
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.org",
                "contacts": "operations@ta.example.org",
            },
            "trust_mark_owners": {
                SIRTIFI_TRUST_MARK_ID: {'jwks': TRUST_MARK_OWNERS_KEYS.export_jwks(),
                                        'sub': TM_OWNERS_ID}
            },
            "trust_mark_issuers": {
                SIRTIFI_TRUST_MARK_ID: TMI_ID
            },
            "endpoints": ['entity_configuration', 'list', 'fetch', 'resolve'],
        }
    },
    TMI_ID: {
        "entity_type": "trust_mark_issuer",
        "trust_anchors": [TA_ID],
        "kwargs": {
            "authority_hints": [TA_ID],
            "trust_mark_entity": {
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
                            "class":
                                "fedservice.trust_mark_entity.server.trust_mark_list.TrustMarkList",
                            "kwargs": {}
                        },
                        "trust_mark_status": {
                            "path": "trust_mark_status",
                            "class":
                                "fedservice.trust_mark_entity.server.trust_mark_status.TrustMarkStatus",
                            "kwargs": {}
                        }
                    }
                }
            }
        }
    },
    FE_ID: {
        "entity_type": "federation_entity",
        "trust_anchors": [TA_ID],
        "kwargs": {
            "authority_hints": [TA_ID],
            "services": ['entity_configuration', 'entity_statement', 'trust_mark_status']
        }
    }
}


@pytest.fixture()
def tm_receiver():
    return "https://entity.example.org"


@pytest.fixture()
def trust_mark_delegation(tm_receiver):
    _jwt = JWT(TRUST_MARK_OWNERS_KEYS, iss=TM_OWNERS_ID, sign_alg='RS256')
    return _jwt.pack({'sub': TMI_ID, "trust_mark_id": SIRTIFI_TRUST_MARK_ID},
                     jws_headers={"typ":"trust-mark-delegation+jwt"})


class TestTrustMarkDelegation():

    @pytest.fixture(autouse=True)
    def setup(self):
        federation = build_federation(FEDERATION_CONFIG)
        self.ta = federation[TA_ID]
        self.fe = federation[FE_ID]
        self.tmi = federation[TMI_ID]

    @pytest.fixture()
    def create_trust_mark(self, trust_mark_delegation, tm_receiver):
        self.tmi.server.trust_mark_entity.trust_mark_specification[SIRTIFI_TRUST_MARK_ID] = {
            "delegation": trust_mark_delegation}
        return self.tmi.server.trust_mark_entity.create_trust_mark(SIRTIFI_TRUST_MARK_ID, tm_receiver)

    def test_delegated_trust_mark(self, create_trust_mark):
        _trust_mark = create_trust_mark
        _jwt = factory(_trust_mark)
        assert 'delegation' in _jwt.jwt.payload()
        _delegation = factory(_jwt.jwt.payload()['delegation'])
        assert _delegation.jwt.payload()['iss'] == TM_OWNERS_ID
        assert _jwt.jwt.payload()['iss'] == TMI_ID
        assert _delegation.jwt.payload()['sub'] == TMI_ID

    def test_verify_trust_mark(self, create_trust_mark):
        _trust_mark = create_trust_mark

        # (1) verify signature and that it is still active
        # a) trust chain for trust mark issuer

        where_and_what = create_trust_chain_messages(self.tmi, self.ta)
        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            verified_trust_mark = self.fe.function.trust_mark_verifier(
                trust_mark=_trust_mark, trust_anchor=self.ta.entity_id)

        assert verified_trust_mark

        # The collector hold all the entity statements/configurations that has been seen so far.
        _collector = self.fe.function.trust_chain_collector

        # Ask the trust mark issuer if the trust mark is still valid
        # get the metadata for the issuer. Should be cached
        tm_issuer_metadata = _collector.get_metadata(TMI_ID)

        service = self.fe.get_service('trust_mark_status')
        req = service.get_request_parameters(
            request_args={
                'sub': verified_trust_mark['sub'],
                'trust_mark_id': verified_trust_mark['trust_mark_id']
            },
            fetch_endpoint=tm_issuer_metadata["federation_entity"][
                'federation_trust_mark_status_endpoint']
        )
        p = urlparse(req['url'])
        tmr = TrustMarkRequest().from_urlencoded(p.query)

        # The response from the Trust Mark issuer
        resp = self.tmi.server.endpoint['trust_mark_status'].process_request(
            tmr.to_dict())
        assert resp == {'response_args': {'active': True}}
