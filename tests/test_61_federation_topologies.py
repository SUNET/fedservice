import pytest
import responses
from cryptojwt.jws.jws import factory

from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import verify_trust_chains
from tests import create_trust_chain_messages
from tests.build_federation import build_federation

TA1_ID = "https://ta.example.org"
TA2_ID = "https://2nd.ta.example.org"
LEAF_ID = "https://rp.example.org"
INTERMEDIATE_ID = "https://intermediate.example.org"

FEDERATION_CONFIG = {
    TA1_ID: {
        "entity_type": "trust_anchor",
        "subordinates": [INTERMEDIATE_ID],
        "kwargs": {
            "preference": {
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.org",
                "contacts": "operations@ta.example.org"
            },
            "endpoints": ['entity_configuration', 'list', 'fetch', 'resolve'],
        }
    },
    TA2_ID: {
        "entity_type": "trust_anchor",
        "subordinates": [INTERMEDIATE_ID],
        "kwargs": {
            "preference": {
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.org",
                "contacts": "operations@ta.example.org"
            },
            "endpoints": ['entity_configuration', 'list', 'fetch', 'resolve'],
        }
    },
    INTERMEDIATE_ID: {
        "entity_type": "intermediate",
        "trust_anchors": [TA2_ID, TA1_ID],
        "subordinates": [LEAF_ID],
        "kwargs": {
            "authority_hints": [TA2_ID, TA1_ID],
        }
    },
    LEAF_ID: {
        "entity_type": "openid_relying_party",
        "trust_anchors": [TA1_ID, TA2_ID],
        "kwargs": {
            "authority_hints": [INTERMEDIATE_ID]
        }
    }
}

# Topology
#
#   TA1                TA2
#    |                  |
#    +-- INTERMEDIATE --+
#              |
#            LEAF
#


class TestServer():

    @pytest.fixture(autouse=True)
    def create_federation(self):
        self.federation_entity = build_federation(FEDERATION_CONFIG)
        self.ta1 = self.federation_entity[TA1_ID]
        self.ta2 = self.federation_entity[TA2_ID]
        self.leaf = self.federation_entity[LEAF_ID]
        self.intermediate = self.federation_entity[INTERMEDIATE_ID]

    def test_multiple_trust_anchors(self):
        _federation_entity = self.leaf

        _msgs = create_trust_chain_messages(self.leaf, self.intermediate, self.ta1)
        _msgs.update(create_trust_chain_messages(self.intermediate, self.ta2))

        assert len(_msgs)

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            _chains, _entity_conf = collect_trust_chains(_federation_entity, self.leaf.entity_id)

        _jws = factory(_entity_conf)
        _unver_entity_conf = _jws.jwt.payload()
        assert _unver_entity_conf['iss'] == self.leaf.entity_id
        assert _unver_entity_conf['sub'] == self.leaf.entity_id

        assert len(_chains) == 2
        assert len(_chains[0]) == 2
        assert len(_chains[1]) == 2

        # Leaf trusts both trust anchors
        _trust_chains = verify_trust_chains(_federation_entity, _chains, _entity_conf)
        assert len(_trust_chains) == 2
        assert _trust_chains[0].iss_path == ['https://rp.example.org',
                                             'https://intermediate.example.org',
                                             'https://2nd.ta.example.org']
        assert _trust_chains[1].iss_path == ['https://rp.example.org',
                                             'https://intermediate.example.org',
                                             'https://ta.example.org']


