from cryptojwt.jws.jws import factory
import pytest

from tests.build_federation import build_federation

LEAF_ID = "https://leaf.example.org"
TA_ID = "https://ta.example.org"

REFEDS_PERSONALIZED = "https://refeds.org/category/personalized/op"

FEDERATION_CONFIG = {
    TA_ID: {
        "entity_type": "trust_anchor",
        "subordinates": [LEAF_ID],
        "kwargs": {
            "preference": {
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.org",
                "contacts": "operations@ta.example.org"
            },
            "endpoints": ['entity_configuration', 'list', 'fetch', 'resolve'],
        }
    },
    LEAF_ID: {
        "entity_type": "federation_entity",
        "trust_anchors": [TA_ID],
        "kwargs": {
            "authority_hints": [TA_ID],
            "preference": {
                "organization_name": "The example federation RP operator",
                "homepage_uri": "https://rp.example.com",
                "contacts": "operations@rp.example.com"
            },
            "self_signed_trust_mark_entity": {
                "class": "fedservice.trust_mark_entity.entity.SelfSignedTrustMarkEntity",
                "kwargs": {
                    "trust_mark_specification": {REFEDS_PERSONALIZED: {}}
                }
            }
        }
    }
}


class TestSelfSignedTrustMark(object):

    @pytest.fixture(autouse=True)
    def setup(self):
        federation = build_federation(FEDERATION_CONFIG)
        self.ta = federation[TA_ID]
        self.leaf = federation[LEAF_ID]

    def test_issue_self_signed_trust_mark(self):
        #
        tm = self.leaf.server.self_signed_trust_mark_entity(REFEDS_PERSONALIZED)
        assert tm

        _jws = factory(tm)
        _payload = _jws.jwt.payload()
        assert _payload['sub'] == _payload["iss"]
        assert _payload['iss'] == self.leaf.entity_id
        assert _payload['trust_mark_type'] == REFEDS_PERSONALIZED

        entity_conf_endpoint = self.leaf.get_endpoint("entity_configuration")
        entity_conf = entity_conf_endpoint.process_request({})

        assert entity_conf
        _jws = factory(entity_conf["response"])
        _payload = _jws.jwt.payload()
        assert _payload["trust_marks"]
        assert len(_payload["trust_marks"]) == 1
        assert _payload["trust_marks"][0] == tm

