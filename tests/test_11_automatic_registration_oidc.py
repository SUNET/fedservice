import os

import pytest
import responses
from idpyoidc.util import rndstr

from fedservice.entity import get_verified_trust_chains
from . import create_trust_chain_messages
from .build_federation import build_federation

BASE_PATH = os.path.abspath(os.path.dirname(__file__))

from .federation_example import TA_IM_RP_OP


class TestAutomatic(object):

    @pytest.fixture(autouse=True)
    def create_federation(self):
        #              TA
        #          +---|---+
        #          |       |
        #          IM      OP
        #          |
        #          RP

        federation = build_federation(TA_IM_RP_OP.FEDERATION_CONFIG)
        self.ta = federation[TA_IM_RP_OP.TA_ID]
        self.rp = federation[TA_IM_RP_OP.RP_ID]
        self.op = federation[TA_IM_RP_OP.OP_ID]
        self.im = federation[TA_IM_RP_OP.IM_ID]

    def test_automatic_registration(self):
        # No clients registered with the OP at the beginning
        assert len(self.op["openid_provider"].get_context().cdb.keys()) == 0

        ####################################################
        # [1] Let the RP gather some provider info

        # Point the RP to the OP
        self.rp["openid_relying_party"].get_context().issuer = self.op.entity_id

        # Create the URLs and messages that will be involved in this process
        _msgs = create_trust_chain_messages(self.op, self.ta)

        # add the jwks_uri
        _jwks_uri = self.op["openid_provider"].get_context().get_preference("jwks_uri")
        if _jwks_uri:
            _msgs[_jwks_uri] = self.op["openid_provider"].keyjar.export_jwks_as_json()

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/entity-statement+jwt"},
                         status=200)

            _trust_chains = get_verified_trust_chains(self.rp,
                                                      self.op["federation_entity"].entity_id)

        self.rp["openid_relying_party"].context.server_metadata = _trust_chains[0].metadata
        self.rp["federation_entity"].client.context.server_metadata = _trust_chains[0].metadata

        _context = self.rp["openid_relying_party"].get_context()

        # automatic registration == not explict registration
        # _context.map_supported_to_preferred(info=_trust_chains[0].metadata["openid_relying_party"])

        _auth_service = self.rp["openid_relying_party"].get_service("authorization")
        state = rndstr()
        authn_request = _auth_service.construct(request_args={"response_type": "code", "state": state})

        # ------------------------------
        # <<<<<< On the OPs side >>>>>>>

        _msgs = create_trust_chain_messages(self.rp, self.im, self.ta)
        # add the jwks_uri
        _jwks_uri = self.rp["openid_relying_party"].get_context().get_preference("jwks_uri")
        if _jwks_uri:
            _msgs[_jwks_uri] = self.rp["openid_relying_party"].keyjar.export_jwks_as_json()

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            # The OP handles the authorization request
            authz_endpoint = self.op["openid_provider"].get_endpoint("authorization")
            req = authz_endpoint.parse_request(authn_request)

        assert "response_type" in req

        # Assert that the client's entity_id has been registered as a client
        assert self.rp.entity_id in self.op["openid_provider"].get_context().cdb
        # Check that the RP's keys are reflected in the OP's keyjar
        assert self.rp.entity_id in self.op["openid_provider"].keyjar
        # There are three RP keys. One EC, one RSA and one OCT
        rp_keyjar = self.rp["openid_relying_party"].keyjar
        op_keyjar = self.op["openid_provider"].keyjar
        for key_type in ["EC", "RSA", "OCT"]:
            for key in rp_keyjar.get_signing_key(key_type=key_type):
                vk = op_keyjar.get_verify_key(key_type=key_type, kid=key.kid, issuer_id=self.rp.entity_id)
                assert vk
