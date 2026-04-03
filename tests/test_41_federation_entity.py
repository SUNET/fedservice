import os

from cryptojwt.jws.jws import factory
import pytest
import responses

from fedservice import get_trust_chain
from fedservice import save_trust_chains
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import get_verified_trust_chains
from fedservice.entity.function import verify_trust_chains
from fedservice.entity.function.policy import TrustChainPolicy
from fedservice.entity.function.trust_chain_collector import TrustChainCollector
from fedservice.entity.function.trust_chain_collector import verify_self_signed_signature
from fedservice.entity.function.trust_mark_verifier import TrustMarkVerifier
from fedservice.entity.function.verifier import TrustChainVerifier
from fedservice.message import EntityStatement
from fedservice.message import ResolveResponse
from tests import create_trust_chain_messages
from tests.build_federation import build_federation

TA1_ID = "https://ta.example.org"
TA2_ID = "https://2nd.ta.example.org"
LEAF_ID = "https://rp.example.org"
INTERMEDIATE_ID = "https://intermediate.example.org"
TENNANT_ID = "https://example.org/tennant1"

# As long as it doesn't provide the Resolve endpoint it doesn't need
# services and functions.
# It must have the openid-federation and fetch endpoints. It may have the
# list and status endpoint. That's the case here.

TA_ENDPOINTS = ["list", "fetch", "entity_configuration"]
BASEDIR = os.path.abspath(os.path.dirname(__file__))
KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

FEDERATION_CONFIG_1 = {
    TA1_ID: {
        "entity_type": "trust_anchor",
        "subordinates": [LEAF_ID],
        "kwargs": {
            "preference": {
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.org",
                "contacts": "operations@ta.example.org"
            },
            "endpoints": TA_ENDPOINTS
        }
    },
    LEAF_ID: {
        "entity_type": "openid_relying_party",
        "trust_anchors": [TA1_ID],
        "kwargs": {
            "preference": {
                "organization_name": "The leaf operator",
                "homepage_uri": "https://rp.example.org",
                "contacts": "operations@rp.example.org"
            },
            "key_config": {"key_defs": KEYDEFS},
            "authority_hints": [TA1_ID],
            "endpoints": ["entity_configuration"]
        }
    }
}


class TestClient(object):
    @pytest.fixture(autouse=True)
    def create_entities(self):
        self.federation_entity = build_federation(FEDERATION_CONFIG_1)
        self.ta_fed = self.federation_entity[TA1_ID]
        self.rp_fed = self.federation_entity[LEAF_ID]["federation_entity"]

    def test_entity_configuration_request(self):
        _serv = self.rp_fed.get_service('entity_configuration')
        _res = _serv.get_request_parameters(request_args={"entity_id": self.ta_fed.entity_id})
        assert _res == {
            'method': 'GET',
            'url': 'https://ta.example.org/.well-known/openid-federation'
        }
        _res = _serv.get_request_parameters(request_args={"entity_id": TENNANT_ID}, tenant=True)
        assert _res == {
            'method': 'GET',
            'url': 'https://example.org/tennant1/.well-known/openid-federation'
        }

    def test_entity_statement_request(self):
        _serv = self.rp_fed.get_service('entity_statement')
        _res = _serv.get_request_parameters(fetch_endpoint=f"{self.ta_fed.entity_id}/fetch", subject=self.rp_fed.entity_id)
        assert _res == {
            'method': 'GET',
            'url': 'https://ta.example.org/fetch?sub=https%3A%2F%2Frp.example.org'
        }

    def test_resolve_request(self):
        _serv = self.rp_fed.get_service('resolve')
        _res = _serv.get_request_parameters(
            request_args={"sub": self.rp_fed.entity_id, "trust_anchor": self.ta_fed.entity_id},
            endpoint=f'{self.ta_fed.entity_id}/.well-known/openid-federation')

        assert _res == {
            'method': 'GET',
            'url': 'https://ta.example.org/.well-known/openid-federation?sub=https%3A'
                   '%2F%2Frp.example.org&trust_anchor=https%3A%2F%2Fta.example.org'

        }


FEDERATION_CONFIG_2 = {
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
    INTERMEDIATE_ID: {
        "entity_type": "intermediate",
        "trust_anchors": [TA1_ID],
        "subordinates": [LEAF_ID],
        "kwargs": {
            "authority_hints": [TA1_ID],
        }
    },
    LEAF_ID: {
        "entity_type": "openid_relying_party",
        "trust_anchors": [TA1_ID],
        "kwargs": {
            "authority_hints": [INTERMEDIATE_ID]
        }
    }
}


class TestServer():

    @pytest.fixture(autouse=True)
    def create_federation(self):
        self.federation_entity = build_federation(FEDERATION_CONFIG_2)
        self.ta = self.federation_entity[TA1_ID]
        self.leaf = self.federation_entity[LEAF_ID]
        self.intermediate = self.federation_entity[INTERMEDIATE_ID]

    # Simple chain setup leaf->intermediate->trust anchor

    def test_entity_setup(self):
        assert self.leaf['federation_entity'].function
        _func = self.leaf['federation_entity'].function
        assert isinstance(_func.trust_chain_collector, TrustChainCollector)
        assert isinstance(_func.trust_mark_verifier, TrustMarkVerifier)
        assert isinstance(_func.policy, TrustChainPolicy)
        assert isinstance(_func.verifier, TrustChainVerifier)

        _client = self.leaf['federation_entity'].client
        assert _client.get_service_names() == {'entity_configuration',
                                               'entity_statement',
                                               'list',
                                               'resolve'}

        assert _client.get_service('entity_configuration').service_name == 'entity_configuration'
        assert _client.get_service('entity_statement').service_name == 'entity_statement'

        assert set(self.leaf['federation_entity'].server.endpoint.keys()) == {
            'entity_configuration'}

    def test_ta_setup(self):
        assert set(self.ta.server.endpoint.keys()) == {'entity_configuration', 'fetch', 'list',
                                                       'resolve'}

    def test_entity_configuration(self):
        _endpoint = self.leaf["federation_entity"].get_endpoint('entity_configuration')
        _req = _endpoint.parse_request({})
        _resp_args = _endpoint.process_request(_req)
        assert set(_resp_args.keys()) == {'response'}
        entity_configuration = verify_self_signed_signature(_resp_args['response'])
        assert entity_configuration['iss'] == self.leaf.entity_id
        assert entity_configuration['sub'] == self.leaf.entity_id
        assert set(entity_configuration['metadata']['federation_entity'].keys()) == set()

    def test_fetch(self):
        _endpoint = self.ta.get_endpoint('fetch')
        _req = _endpoint.parse_request({"sub": self.intermediate.entity_id})
        _resp_args = _endpoint.process_request(_req)
        assert _resp_args

        _jws = factory(_resp_args["response_msg"])
        payload = _jws.jwt.payload()
        entity_statement = EntityStatement(**payload)
        entity_statement.verify()
        assert entity_statement['iss'] == self.ta.entity_id
        assert entity_statement['sub'] == self.intermediate.entity_id
        assert entity_statement['authority_hints'] == [self.ta.entity_id]

    def test_list(self):
        _endpoint = self.ta.get_endpoint('list')
        _req = _endpoint.parse_request({})
        _resp_args = _endpoint.process_request(_req)
        assert _resp_args
        assert _resp_args['response_msg'] == f'["{self.intermediate.entity_id}"]'

    def test_resolve(self):
        _msgs = create_trust_chain_messages(self.leaf["federation_entity"],
                                            self.intermediate,
                                            self.ta)

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            _endpoint = self.ta.get_endpoint('resolve')
            _req = _endpoint.parse_request({
                "sub": self.leaf.entity_id,
                "trust_anchor": self.ta.entity_id
            })
            _resp_args = _endpoint.process_request(_req)

        assert _resp_args
        _jws = factory(_resp_args["response_args"])
        payload = _jws.jwt.payload()
        entity_statement = ResolveResponse(**payload)
        entity_statement.verify()


FEDERATION_CONFIG_3 = {
    TA1_ID: {
        "entity_type": "trust_anchor",
        "subordinates": [INTERMEDIATE_ID],
        "kwargs": {
            "preference": {
                "organization_name": "The 1st example federation operator",
                "homepage_uri": "https://ta_one.example.org",
                "contacts": "operations@ta_one.example.org"
            },
        }
    },
    TA2_ID: {
        "entity_type": "trust_anchor",
        "subordinates": [LEAF_ID],
        "kwargs": {
            "preference": {
                "organization_name": "The 2nd example federation operator",
                "homepage_uri": "https://ta_two.example.org",
                "contacts": "operations@ta_two.example.org"
            },
        }
    },
    INTERMEDIATE_ID: {
        "entity_type": "intermediate",
        "trust_anchors": [TA1_ID],
        "subordinates": [LEAF_ID],
        "kwargs": {
            "authority_hints": [TA1_ID],
        }
    },
    LEAF_ID: {
        "entity_type": "openid_relying_party",
        "trust_anchors": [TA1_ID, TA2_ID],
        "kwargs": {
            "authority_hints": [INTERMEDIATE_ID, TA2_ID]
        }
    }
}


class TestFunction:

    @pytest.fixture(autouse=True)
    def create_entities(self):
        # Two chains leaf->intermediate->trust_anchor_1 and leaf->trust_anchor_2
        #       TA1     TA2_ID
        #       |      |
        #      IM      |
        #       \      |
        #        +--- LEAF

        self.federation_entity = build_federation(FEDERATION_CONFIG_3)
        self.ta1 = self.federation_entity[TA1_ID]
        self.ta2 = self.federation_entity[TA2_ID]
        self.leaf = self.federation_entity[LEAF_ID]
        self.intermediate = self.federation_entity[INTERMEDIATE_ID]

    def test_trust_chains_to_intermediate(self):
        _federation_entity = self.intermediate
        # Should not be necessary. It's pytest that messes things up
        if 'https://2nd.ta.example.org' in _federation_entity.function.trust_chain_collector.trust_anchors:
            del _federation_entity.function.trust_chain_collector.trust_anchors['https://2nd.ta.example.org']

        _msgs = create_trust_chain_messages(self.leaf, self.intermediate, self.ta1)
        _msgs.update(create_trust_chain_messages(self.leaf, self.ta2))

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

        # Intermediate doesn't have TA2_ID as trust anchor
        _trust_chains = verify_trust_chains(_federation_entity, _chains, _entity_conf)
        assert len(_trust_chains) == 1

    def test_trust_chains_to_leaf(self):
        _federation_entity = self.leaf

        _msgs = create_trust_chain_messages(self.leaf, self.intermediate, self.ta1)
        _msgs.update(create_trust_chain_messages(self.leaf, self.ta2))

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

        # Leaf trusts both trust anchors
        _trust_chains = verify_trust_chains(_federation_entity, _chains, _entity_conf)
        assert len(_trust_chains) == 2

    def test_upstream_context_attribute(self):
        leaf_fe = self.leaf["federation_entity"]
        assert leaf_fe.client.upstream_get('context_attribute', 'entity_id') == LEAF_ID
        assert leaf_fe.function.upstream_get('context_attribute', 'entity_id') == LEAF_ID
        assert leaf_fe.function.policy.upstream_get('context_attribute', 'entity_id') == LEAF_ID
        assert leaf_fe.server.upstream_get('context_attribute', 'entity_id') == LEAF_ID

    def test_upstream_attribute(self):
        leaf_fe = self.leaf["federation_entity"]
        assert leaf_fe.client.upstream_get('attribute', 'keyjar') == leaf_fe.keyjar
        assert leaf_fe.function.upstream_get('attribute', 'keyjar') == leaf_fe.keyjar
        assert leaf_fe.function.policy.upstream_get('attribute', 'keyjar') == leaf_fe.keyjar
        assert leaf_fe.server.upstream_get('attribute', 'keyjar') == leaf_fe.keyjar

    def test_trust_anchors_attribute(self):
        # This to deal with some strange spill over
        anchors = set(self.leaf["federation_entity"].trust_anchors.keys())
        for x in ['https://swamid.se', 'https://anchor.example.com', 'https://feide.no']:
            if x in anchors:
                anchors.remove(x)

        assert anchors == {'https://ta.example.org', 'https://2nd.ta.example.org'}

    def test_save_trust_chains(self):
        _msgs = create_trust_chain_messages(self.leaf, self.intermediate, self.ta1)
        _msgs.update(create_trust_chain_messages(self.leaf, self.ta2))

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            _trust_chains = get_verified_trust_chains(self.leaf,
                                                      self.leaf["federation_entity"].entity_id)

        federation_context = self.leaf["federation_entity"].context
        save_trust_chains(federation_context, _trust_chains)
        assert set(federation_context.trust_chain.keys()) == {LEAF_ID}
        assert set(federation_context.trust_chain[LEAF_ID].keys()) == {TA1_ID, TA2_ID}

        trust_chain = get_trust_chain(federation_context, LEAF_ID, TA1_ID)
        assert trust_chain
        assert trust_chain.anchor == TA1_ID
        assert trust_chain.iss_path == [LEAF_ID, INTERMEDIATE_ID, TA1_ID]
