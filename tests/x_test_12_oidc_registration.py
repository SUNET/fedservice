import os

import pytest
import responses
from cryptojwt.jws.jws import factory

from fedservice.defaults import WELL_KNOWN_FEDERATION_ENDPOINT
from . import create_trust_chain_messages
from .build_federation import build_federation

BASE_PATH = os.path.abspath(os.path.dirname(__file__))


class TestExplicit(object):

    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        #              TA
        #          +---|---+
        #          |       |
        #          IM      OP
        #          |
        #          RP

        federation_spec = {
            "https://ta.example.org": {
                "entity_type": "trust_anchor",
                "subordinates": ["https://int.example.org", "https://op.example.org"],
                "kwargs": {
                    "preference": {
                        "organization_name": "The example federation operator",
                        "homepage_uri": "https://ta.example.org",
                        "contacts": "operations@ta.example.org"
                    },
                }
            },
            "https://int.example.org": {
                "entity_type": "intermediate",
                "trust_anchors": ["https://ta.example.org"],
                "subordinates": ["https://rp.example.org"],
                "kwargs": {
                    "authority_hints": ["https://ta.example.org"],
                }
            },
            "https://rp.example.org": {
                "entity_type": "openid_relying_party",
                "trust_anchors": ["https://ta.example.org"],
                "kwargs": {
                    "authority_hints": ["https://int.example.org"]
                }
            },
            "https://op.example.org": {
                "entity_type": "openid_provider",
                "trust_anchors": ["https://ta.example.org"],
                "kwargs": {
                    "authority_hints": ["https://int.example.org"]
                }
            }
        }
        self.federation = build_federation(federation_spec)
        self.op = self.federation["https://op.example.org"]
        self.rp = self.federation["https://rp.example.org"]
        self.im = self.federation["https://int.example.org"]
        self.ta = self.federation["https://ta.example.org"]

    def test_registration_verification(self):
        # No clients registered with the OP at the beginning
        assert len(self.op['openid_provider'].get_context().cdb.keys()) == 0

        ####################################################
        # [1] Let the RP do some provider info discovery
        # Point the RP to the OP
        self.rp['openid_relying_party'].get_context().issuer = self.op.entity_id

        # Create the URLs and messages that will be involved in this process
        _msgs = create_trust_chain_messages(self.op, self.ta)

        # add the jwks_uri
        # _jwks_uri = self.op['openid_provider'].get_context().get_preference('jwks_uri')
        # _msgs[_jwks_uri] = self.op['openid_provider'].keyjar.export_jwks_as_json()

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            self.rp['openid_relying_party'].do_request('provider_info')

        # the provider info should have been updated

        assert self.rp['openid_relying_party'].get_context().provider_info

        ####################################################
        # [2] Let the RP construct the registration request

        _reg_service = self.rp['openid_relying_party'].get_service('registration')
        reg_request = _reg_service.construct()

        ###############################################################
        # [3] The OP receives a registration request and responds to it
        _msgs = create_trust_chain_messages(self.rp.entity_id, self.im, self.ta)
        # add the jwks_uri
        # _jwks_uri = self.op['openid_provider'].get_preference('jwks_uri')
        # _msgs[_jwks_uri] = self.op['openid_provider'].keyjar.export_jwks_as_json()

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         headers={"Content-Type": "application/json"}, status=200)

            # The OP handles the registration request
            resp = self.op['openid_provider'].get_endpoint('registration').process_request(
                reg_request)

        assert resp["response_code"] == 201

        _jws = factory(resp['response_msg'])
        _payload = _jws.jwt.payload()
        assert _payload['iss'] == self.op.entity_id
        assert _payload['sub'] == self.rp.entity_id
        assert _payload['trust_anchor'] == self.ta.entity_id
        assert _payload['aud'] == self.rp.entity_id

        ###########################################################################
        # [4] The RP receives the registration response and calculates the preference

        _msgs = create_trust_chain_messages(self.rp, self.im, self.ta)
        # Cached
        del _msgs[WELL_KNOWN_FEDERATION_ENDPOINT.format(self.ta.entity_id)]
        # _msgs = {}
        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         headers={"Content-Type": "application/json"}, status=200)

            reg_resp = _reg_service.parse_response(resp['response_msg'])

        assert reg_resp
        assert 'client_id' in reg_resp
