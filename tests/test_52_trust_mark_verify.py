from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.util import rndstr
import pytest
import responses

from fedservice.defaults import LEAF_ENDPOINTS
from fedservice.trust_mark_entity.entity import create_trust_mark
from fedservice.utils import make_federation_combo
from fedservice.utils import make_federation_entity
from tests import create_trust_chain_messages
from tests.build_federation import build_federation

TA_ENDPOINTS = ["list", "fetch", "entity_configuration"]

TA_ID = "https://ta.example.org"
RP_ID = "https://rp.example.org"
TRUST_MARK_ISSUER_ID = "https://trust_mark_issuer.example.org"
IM_ID = "https://im.example.org"

TM_ID = "https://refeds.org/wp-content/uploads/2016/01/Sirtfi-1.0.pdf"

FEDERATION_CONFIG = {
    TA_ID: {
        "entity_type": "trust_anchor",
        "subordinates": [IM_ID, TRUST_MARK_ISSUER_ID],
        "kwargs": {
            "preference": {
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.org",
                "contacts": "operations@ta.example.org"
            },
            "endpoints": ['entity_configuration', 'list', 'fetch', 'resolve'],
            "trust_mark_issuers": {
                "https://refeds.org/sirtfi": [TRUST_MARK_ISSUER_ID]
            }
        }
    },
    IM_ID: {
        "entity_type": "intermediate",
        "trust_anchors": [TA_ID],
        "subordinates": [RP_ID],
        "kwargs": {
            "authority_hints": [TA_ID],
        }
    },
    TRUST_MARK_ISSUER_ID: {
        "entity_type": "trust_mark_issuer",
        "trust_anchors": [TA_ID],
        "kwargs": {
            "authority_hints": [TA_ID],
        },
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
                        "class": "fedservice.trust_mark_entity.server.trust_mark_list"
                                 ".TrustMarkList",
                        "kwargs": {}
                    },
                    "trust_mark_status": {
                        "path": "trust_mark_status",
                        "class": "fedservice.trust_mark_entity.server.trust_mark_status"
                                 ".TrustMarkStatus",
                        "kwargs": {}
                    }
                }
            }
        }
    },
    RP_ID: {
        "entity_type": "openid_relying_party",
        "trust_anchors": [TA_ID],
        "kwargs": {
            "authority_hints": [IM_ID],
            "preference": {
                "organization_name": "The example federation RP operator",
                "homepage_uri": "https://rp.example.com",
                "contacts": "operations@rp.example.com"
            }
        }
    }
}


class TestComboCollect(object):

    @pytest.fixture(autouse=True)
    def setup(self):
        #     Federation tree
        #
        #            TA
        #        +---|-------+
        #        |           |
        #        IM      TRUST_MARK_ISSUER
        #        |
        #        RP

        federation = build_federation(FEDERATION_CONFIG)
        self.ta = federation[TA_ID]
        self.rp = federation[RP_ID]
        self.im = federation[IM_ID]
        self.tmi = federation[TRUST_MARK_ISSUER_ID]

    def test_setup(self):
        assert self.ta
        assert self.ta.server
        assert set(self.ta.server.subordinate.keys()) == {TRUST_MARK_ISSUER_ID, IM_ID}

    def test_trust_mark_verifier(self):
        where_and_what = create_trust_chain_messages(self.tmi, self.ta)

        _trust_mark = create_trust_mark(entity_id=self.tmi.entity_id,
                                        keyjar=self.tmi.get_attribute('keyjar'),
                                        trust_mark_type="https://refeds.org/sirtfi",
                                        sub=self.rp.entity_id,
                                        lifetime=3600,
                                        reference='https://refeds.org/sirtfi')

        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            verified_trust_mark = self.rp["federation_entity"].function.trust_mark_verifier(
                trust_mark=_trust_mark, trust_anchor=self.ta.entity_id)

        assert verified_trust_mark
