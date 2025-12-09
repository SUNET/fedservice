import pytest
import responses

from fedservice.entity.function import apply_policies
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import verify_trust_chains
from tests import create_trust_chain_messages
from tests.build_federation import build_federation

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

TA_ID = "https://ta.example.org"
RP_ID = "https://rp.example.org"
OP_ID = "https://op.example.org"
IM_ID = "https://im.example.org"

TA_ENDPOINTS = ["list", "fetch", "entity_configuration"]

FEDERATION_CONFIG = {
    TA_ID: {
        "federation_entity": {
            "subordinates": [IM_ID, OP_ID],
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
            "subordinates": [RP_ID],
            "authority_hints": [TA_ID],
            "endpoint": ['entity_configuration', 'list', 'fetch', 'resolve'],
        }
    },
    OP_ID: {
        "federation_entity": {
            "trust_anchors": [TA_ID],
            "authority_hints": [TA_ID]
        },
        "openid_provider": {},
    },
    RP_ID: {
        "federation_entity": {
            "trust_anchors": [TA_ID],
            "authority_hints": [IM_ID],
            "preference": {
                "organization_name": "The example federation RP operator",
                "homepage_uri": "https://rp.example.com",
                "contacts": "operations@rp.example.com"
            }
        },
        "openid_relying_party": {}
    }
}


class TestComboCollect(object):

    @pytest.fixture(autouse=True)
    def setup(self):
        #              TA
        #          +---|---+
        #          |       |
        #          IM      OP
        #          |
        #          RP

        federation = build_federation(FEDERATION_CONFIG)
        self.ta = federation[TA_ID]
        self.im = federation[IM_ID]
        self.op = federation[OP_ID]
        self.rp = federation[RP_ID]

    def test_setup(self):
        assert self.ta
        assert self.ta.server
        assert set(self.ta.server.subordinate.keys()) == {OP_ID, IM_ID}

    def test_collect_trust_chain(self):
        # Need 2 entity configurations (leaf and TA) and 1 entity statement (TA about leaf
        # leaf = OP

        _msg = create_trust_chain_messages(self.rp, self.im, self.ta)

        assert len(_msg) == 5

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msg.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            chains, leaf_ec = collect_trust_chains(self.op, RP_ID)

        assert len(chains) == 1
        assert len(chains[0]) == 2

        trust_chains = verify_trust_chains(self.op, chains, leaf_ec)
        assert trust_chains
        assert len(trust_chains) == 1

        trust_chains = apply_policies(self.op, trust_chains)
        assert trust_chains
        assert len(trust_chains) == 1

        trust_chain = trust_chains[0]
        assert trust_chain.metadata
        assert set(trust_chain.metadata.keys()) == {'openid_relying_party', 'federation_entity'}
        assert set(trust_chain.metadata['federation_entity'].keys()) == {
            'organization_name', 'homepage_uri', 'contacts'}
        assert trust_chain.metadata['federation_entity']["contacts"] == 'operations@rp.example.com'
