import pytest
import responses

from fedservice.entity.function import apply_policies
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import get_verified_trust_chains
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
            "subordinates": [IM_ID, OP_ID],
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
                "organization_uri": "https://rp.example.com",
                "contacts": "operations@rp.example.com"
            }
        },
        "openid_relying_party": {},
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

        assert self.op
        assert set(self.op.keys()) == {'federation_entity', 'openid_provider'}

        assert self.rp
        assert set(self.rp.keys()) == {'federation_entity', 'openid_relying_party'}

    def test_collect_trust_chain(self):
        # Need 2 entity configurations (leaf and TA) and 1 entity statement (TA about leaf)
        # leaf = OP

        _msgs = create_trust_chain_messages(self.rp, self.im, self.ta)

        assert len(_msgs) == 5

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            chains, leaf_ec = collect_trust_chains(self.op, RP_ID)

        assert len(chains) == 1

        trust_chains = verify_trust_chains(self.rp, chains, leaf_ec)
        trust_chains = apply_policies(self.rp, trust_chains)
        assert len(trust_chains) == 1

        trust_chain = trust_chains[0]

        assert trust_chain.metadata
        assert set(trust_chain.metadata.keys()) == {'federation_entity', 'openid_relying_party'}
        assert set(trust_chain.metadata['federation_entity'].keys()) == {
            'organization_name', 'organization_uri', 'contacts', 'endpoint_auth_signing_alg_values_supported'}

    def test_provider_info_discovery(self):
        _rp_fe = self.rp['federation_entity']
        # _rp_fe.context.issuer = self.op.entity_id
        entity_conf = _rp_fe.get_service('entity_configuration')

        # Just to verify that the request URL is the right one
        req = entity_conf.get_request_parameters({"entity_id": self.op.entity_id})
        assert req['url'] == 'https://op.example.org/.well-known/openid-federation'

        where_and_what = create_trust_chain_messages(self.op, self.ta)

        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/entity-statement+jwt"},
                         status=200)

            trust_chains = get_verified_trust_chains(_rp_fe, self.op.entity_id)

        assert len(trust_chains) == 1
        assert set(trust_chains[0].metadata.keys()) == {'federation_entity', 'openid_provider'}
