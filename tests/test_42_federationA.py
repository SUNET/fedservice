import pytest
import responses

from fedservice.entity.function import apply_policies
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import verify_trust_chains
from tests import create_trust_chain_messages
from tests.build_federation import build_federation

TA_ID = "https://ta.example.org"
RP_ID = "https://rp.example.org"
OP_ID = "https://op.example.org"

FEDERATION_CONFIG = {
    TA_ID: {
        "federation_entity": {
            "subordinate": [RP_ID, OP_ID],
            "preference": {
                "organization_name": "The example federation operator",
                "organization_uri": "https://ta.example.org",
                "contacts": "operations@ta.example.org"
            },
            "endpoint": ['entity_configuration', 'list', 'fetch', 'resolve'],

        },
    },
    OP_ID: {
        "federation_entity": {
            "trust_anchors": [TA_ID],
            "authority_hints": [TA_ID],
        },
        "openid_provider": {},
    },
    RP_ID: {
        "federation_entity": {
            "trust_anchors": [TA_ID],
            "authority_hints": [TA_ID]
        },
        "openid_relying_party": {},
    }
}


class TestComboCollect(object):

    @pytest.fixture(autouse=True)
    def setup(self):
        #          TA
        #          |
        #       +--+--+
        #       |     |
        #      RP     OP

        self.federation = build_federation(FEDERATION_CONFIG)
        self.ta = self.federation[TA_ID]
        self.op = self.federation[OP_ID]
        self.rp = self.federation[RP_ID]

    def test_setup(self):
        assert self.ta
        assert self.ta.server
        assert set(self.ta.server.subordinate.keys()) == {OP_ID, RP_ID}

    def test_collect_trust_chain(self):
        # Need 2 entity configurations (OP and TA) and 1 entity statement (TA about the OP)
        _msgs = create_trust_chain_messages(self.op, self.ta)

        assert len(_msgs) == 3

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            chains, leaf_ec = collect_trust_chains(self.rp, OP_ID)

        assert len(chains) == 1

        trust_chains = verify_trust_chains(self.rp, chains, leaf_ec)
        trust_chains = apply_policies(self.rp, trust_chains)
        assert len(trust_chains) == 1

        trust_chain = trust_chains[0]

        assert trust_chain.metadata
        assert set(trust_chain.metadata.keys()) == {'federation_entity', 'openid_provider'}
        assert set(trust_chain.metadata['federation_entity'].keys()) == {'endpoint_auth_signing_alg_values_supported'}

        assert trust_chain.is_expired() is False

    def test_collect_trust_chain_2(self):
        # Trust chain OP->TA
        _msgs = create_trust_chain_messages(self.op, self.ta)

        assert len(_msgs) == 3

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            chains, leaf_ec = collect_trust_chains(self.rp, OP_ID)

        assert len(chains) == 1

        # Trust chain RP->TA
        _msgs = create_trust_chain_messages(self.rp, self.ta)

        del _msgs['https://ta.example.org/.well-known/openid-federation']
        assert len(_msgs) == 2

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            chains_1, leaf_ec_1 = collect_trust_chains(self.rp, RP_ID)

        assert len(chains_1) == 1

        # Trust chain RP->TA Second time
        chains_2, leaf_ec_2 = collect_trust_chains(self.rp, RP_ID)

        assert leaf_ec_2
        assert leaf_ec_1 == leaf_ec_2
        assert chains_1 == chains_2
