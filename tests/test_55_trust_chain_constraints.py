import pytest
import responses
from cryptojwt.jws.jws import factory

from fedservice.entity.function import apply_policies
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import verify_trust_chains
from tests import create_trust_chain_messages
from tests.build_federation import build_federation

TA_ID = "https://ta.example.org"
LEAF_ID = "https://leaf.example.org"
IM_ID = "https://im.example.org"
RP_ID = "https://rp.example.org"

FEDERATION_CONFIG = {
    TA_ID: {
        "federation_entity": {
            "subordinates": [IM_ID, LEAF_ID],
            "preference": {
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.org",
                "contacts": "operations@ta.example.org"
            },
            "endpoint": ['entity_configuration', 'list', 'fetch', 'resolve'],
        }
    },
    IM_ID: {
        "federation_entity": {
            "trust_anchors": [TA_ID],
            "subordinates": [RP_ID, LEAF_ID],
            "authority_hints": [TA_ID],
            "endpoint": ['entity_configuration', 'list', 'fetch', 'resolve']
        }
    },
    LEAF_ID: {
        "federation_entity": {
            "trust_anchors": [TA_ID],
            "authority_hints": [IM_ID]
        }
    },
    RP_ID: {
        "federation_entity": {
            "trust_anchors": [TA_ID],
            "authority_hints": [IM_ID],
            "preference": {
                "organization_name": "The example federation RP operator",
                "homepage_uri": "https://rp.example.com",
                "contacts": "operations@rp.example.com",
            }
        },
        "openid_relying_party": {
            "preference": {
                "grant_types": ['authorization_code', 'refresh_token']
            }
        }
    }
}


class TestConstraints(object):

    @pytest.fixture(autouse=True)
    def setup(self):
        #          TA
        #          |
        #          IM
        #          |
        #       +--+--+
        #       |     |
        #      RP   LEAF

        federation = build_federation(FEDERATION_CONFIG)
        self.ta = federation[TA_ID]
        self.im = federation[IM_ID]
        self.leaf = federation[LEAF_ID]
        self.rp = federation[RP_ID]

        #########################
        # Policies
        # entity specific
        self.ta.server.policy[IM_ID] = {
            "metadata_policy": {
                "openid_relying_party": {
                    "application_type": {
                        "one_of": ["web", "native"]
                    },
                    "grant_types": {
                        "subset_of": ["authorization_code", "refresh_token"]
                    }
                },
                'federation_entity': {
                    "contacts": {
                        'add': ['ops@ta.example.com']
                    }
                }
            }
        }
        # entity type specific
        self.im.server.policy['openid_relying_party'] = {
            "metadata_policy": {
                "contacts": {
                    "add": ["ops@example.org", "ops@example.com"]
                },
                "grant_types": {
                    "subset_of": ["authorization_code", "refresh_token"]
                }
            },
            'metadata': {
                "application_type": "web",
                "organization_name": "EXAMPLE INC.",
                "logo_uri": "https://www.example.com/images/32x32.png",
            }
        }

    def test_intermediate(self):
        _endpoint = self.ta.server.get_endpoint('fetch')
        _req = _endpoint.parse_request({'iss': self.ta.entity_id, 'sub': self.im.entity_id})
        _jws = factory(_endpoint.process_request(_req)["response_msg"])
        _payload = _jws.jwt.payload()
        assert _payload
        assert 'metadata_policy' in _payload

        _msgs = create_trust_chain_messages(self.im, self.ta)

        assert len(_msgs) == 3

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            chains, leaf_ec = collect_trust_chains(self.leaf, IM_ID)

        assert len(chains) == 1

        trust_chains = verify_trust_chains(self.leaf, chains, leaf_ec)
        trust_chains = apply_policies(self.leaf, trust_chains)
        assert len(trust_chains) == 1
        assert 'ops@ta.example.com' in trust_chains[0].metadata['federation_entity']['contacts']

    def test_leaf(self):
        _endpoint = self.im.server.get_endpoint('fetch')
        _req = _endpoint.parse_request({'sub': self.leaf.entity_id})
        _jws = factory(_endpoint.process_request(_req)["response_msg"])
        _payload = _jws.jwt.payload()
        assert _payload
        # The intermediate has no specific policy for the leaf and none general for entity types
        assert 'metadata_policy' not in _payload and 'metadata' not in _payload

        _msgs = create_trust_chain_messages(self.leaf, self.im, self.ta)

        assert len(_msgs) == 5

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            chains, leaf_ec = collect_trust_chains(self.leaf, LEAF_ID)

        assert len(chains) == 1

        trust_chains = verify_trust_chains(self.leaf, chains, leaf_ec)
        trust_chains = apply_policies(self.leaf, trust_chains)
        assert len(trust_chains) == 1
        assert 'ops@ta.example.com' in trust_chains[0].metadata['federation_entity']['contacts']

    def test_rp(self):
        _endpoint = self.im.server.get_endpoint('fetch')
        _req = _endpoint.parse_request({'sub': self.rp.entity_id})
        _jws = factory(_endpoint.process_request(_req)["response_msg"])
        _payload = _jws.jwt.payload()
        assert _payload
        assert 'metadata_policy' in _payload and 'metadata' in _payload

        _msgs = create_trust_chain_messages(self.rp, self.im, self.ta)

        assert len(_msgs) == 5

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            chains, rp_ec = collect_trust_chains(self.leaf, RP_ID)

        assert len(chains) == 1

        trust_chains = verify_trust_chains(self.leaf, chains, rp_ec)
        trust_chains = apply_policies(self.leaf, trust_chains)
        assert len(trust_chains) == 1
        _metadata = trust_chains[0].metadata

        assert 'ops@ta.example.com' in _metadata['federation_entity']['contacts']
        assert set(_metadata['openid_relying_party']['grant_types']) == {'authorization_code', 'refresh_token'}
