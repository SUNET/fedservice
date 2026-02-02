import pytest
import responses

from fedservice.entity.function import apply_policies
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import get_verified_trust_chains
from fedservice.entity.function import pick_trust_anchors
from fedservice.entity.function import verify_trust_chains
from tests import create_trust_chain_messages
from tests.build_federation import build_federation

TA_ID = "https://ta.example.org"
RP_ID = "https://rp.example.org"
OP_ID = "https://op.example.org"
IM_ID = "https://im.example.org"

FEDERATION_CONFIG = {
    TA_ID: {
        "federation_entity": {
            "subordinate": [IM_ID, OP_ID],
            "preference": {
                "organization_name": "The example federation operator",
                "organization_uri": "https://ta.example.org",
                "contacts": "operations@ta.example.org"
            },
            "endpoint": ['entity_configuration', 'list', 'fetch', 'resolve'],
        }
    },
    IM_ID: {
        "federation_entity": {
            "trust_anchors": [TA_ID],
            "subordinate": [RP_ID],
            "authority_hints": [TA_ID],
            "endpoint": ['entity_configuration', 'list', 'fetch', 'resolve'],
        }
    },
    OP_ID: {
        "federation_entity": {
            "trust_anchors": [TA_ID],
            "authority_hints": [TA_ID],
            "trust_anchor_hints": [TA_ID]
        },
        "openid_provider": {},
    },
    RP_ID: {
        "federation_entity": {
            "trust_anchors": [TA_ID],
            "authority_hints": [IM_ID],
            "preference": {
                "organization_name": "The example federation RP operator",
                "organization_uri": "https://rp.example.com",
                "contacts": "operations@rp.example.com"
            }
        },
        "openid_relying_party": {},
    }
}


class TestAnchorHints(object):

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


    def test_pick_ta_with_trust_anchor_hints(self):
        where_and_what = create_trust_chain_messages(self.op)

        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/entity-statement+jwt"},
                         status=200)

            trust_anchors = pick_trust_anchors(self.rp["federation_entity"], OP_ID)

        assert len(trust_anchors) == 1
        assert TA_ID in trust_anchors

    def test_pick_ta_without_trust_anchor_hints(self):
        where_and_what = create_trust_chain_messages(self.rp, self.im, self.ta)

        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/entity-statement+jwt"},
                         status=200)

            trust_anchors = pick_trust_anchors(self.op['federation_entity'], RP_ID)

        assert len(trust_anchors) == 1
        assert TA_ID in trust_anchors

