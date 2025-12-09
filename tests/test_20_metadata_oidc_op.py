import pytest

from tests.build_federation import build_federation

TA_ID = "https://ta.example.org"
RP_ID = "https://rp.example.org"
OP_ID = "https://op.example.org"
IM_ID = "https://im.example.org"

FEDERATION_CONFIG = {
    TA_ID: {
        "federation_entity": {
            "trust_anchors": [TA_ID],
            "authority_hints": [TA_ID],
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
        }
    },
    OP_ID: {
        "federation_entity": {
            "trust_anchors": [TA_ID],
            "authority_hints": [TA_ID]
        },
        "openid_provider": {}
    },
    RP_ID: {
        "federation_entity": {
            "trust_anchors": [TA_ID],
            "authority_hints": [IM_ID],
        },
        "openid_relying_party": {
            "preference": {
                "organization_name": "The example federation RP operator",
                "homepage_uri": "https://rp.example.com",
                "contacts": "operations@rp.example.com"
            }
        }
    }
}


class TestClient(object):

    @pytest.fixture(autouse=True)
    def create_entities(self):
        self.federation_entity = build_federation(FEDERATION_CONFIG)
        self.ta = self.federation_entity[TA_ID]
        self.rp = self.federation_entity[RP_ID]
        self.op = self.federation_entity[OP_ID]
        self.im = self.federation_entity[IM_ID]

    def test_ta_metadata(self):
        metadata = self.ta.get_metadata()
        assert metadata
