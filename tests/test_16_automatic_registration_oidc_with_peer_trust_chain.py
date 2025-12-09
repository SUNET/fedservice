import os

import pytest
import responses
from idpyoidc.util import rndstr

from fedservice import get_payload
from fedservice.entity.function import get_verified_trust_chains
from . import create_trust_chain_messages
from .build_federation import build_federation

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.join(BASE_PATH, "base_data")

from .federation_example import TA_IM_RP_OP


class TestAutomatic(object):

    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        #              TA
        #          +---|---+
        #          |       |
        #          IM     OP
        #          |
        #          OC

        federation = build_federation(TA_IM_RP_OP.FEDERATION_CONFIG)
        self.ta = federation[TA_IM_RP_OP.TA_ID]
        self.rp = federation[TA_IM_RP_OP.RP_ID]
        self.op = federation[TA_IM_RP_OP.OP_ID]
        self.im = federation[TA_IM_RP_OP.IM_ID]

        self.entity_config_service = self.rp["federation_entity"].get_service(
            "entity_configuration")
        self.entity_config_service.upstream_get("context").issuer = TA_IM_RP_OP.OP_ID
        self.registration_service = self.rp["federation_entity"].get_service("registration")

    def create_trust_chains(self):
        # Collect information about the OP
        _msgs = create_trust_chain_messages(self.op, self.ta)

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/entity-statement+jwt"},
                         status=200)

            _trust_chains = get_verified_trust_chains(self.rp, self.op["federation_entity"].entity_id)

        self.rp["openid_relying_party"].context.server_metadata = _trust_chains[0].metadata
        self.rp["federation_entity"].client.context.server_metadata = _trust_chains[0].metadata

        peer_trust_chain = _trust_chains[0].chain[:]
        peer_trust_chain.reverse()

        _msgs = create_trust_chain_messages(self.rp, self.im, self.ta)

        # This has been seen already
        del _msgs['https://ta.example.org/.well-known/openid-federation']

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/entity-statement+jwt"},
                         status=200)

            _trust_chains = get_verified_trust_chains(self.rp, self.rp["federation_entity"].entity_id)

        trust_chain = _trust_chains[0].chain[:]
        trust_chain.reverse()

        return trust_chain, peer_trust_chain

    def test_automatic_registration_new_client_id(self):
        # No clients registered with the OP at the beginning
        assert len(self.op["openid_provider"].get_context().cdb.keys()) == 0

        ####################################################
        # [1] Let the RP gather some provider info

        # Point the RP to the OP
        self.rp["openid_relying_party"].get_context().issuer = self.op.entity_id

        trust_chain, peer_trust_chain = self.create_trust_chains()

        req_args = {"response_type": "code", "state": rndstr(),
                    "entity_id": self.rp["federation_entity"].entity_id,
                    "peer_trust_chain": peer_trust_chain,
                    'trust_chain': trust_chain,
                    'aud': self.op.entity_id}

        # create the authorization request

        _auth_service = self.rp["openid_relying_party"].get_service("authorization")
        authn_request = _auth_service.construct(request_args=req_args)

        # ------------------------------
        # <<<<<< On the OP's side >>>>>>>

        _msgs = create_trust_chain_messages(self.rp, self.im, self.ta)
        # add the jwks_uri
        _jwks_uri = self.rp["openid_relying_party"].get_context().get_preference("jwks_uri")
        if _jwks_uri:
            _msgs[_jwks_uri] = self.rp["openid_relying_party"].keyjar.export_jwks_as_json()
        # This has been seen already
        # del _msgs['https://rp.example.org/.well-known/openid-federation']
        # del _msgs['https://im.example.org/.well-known/openid-federation']
        # del _msgs['https://im.example.org/fetch']
        # del _msgs['https://ta.example.org/.well-known/openid-federation']
        # del _msgs['https://ta.example.org/fetch']

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/entity-statement+jwt"},
                         status=200)

            # The OP handles the authorization request
            _authz_endpoint = self.op["openid_provider"].get_endpoint("authorization")
            req = _authz_endpoint.parse_request(authn_request)

        assert "response_type" in req

        # Assert that the client's entity_id has been registered as a client
        assert self.rp.entity_id in self.op["openid_provider"].get_context().cdb

    def test_authz_request_with_trust_chain(self):
        # No clients registered with the OP at the beginning
        assert len(self.op["openid_provider"].get_context().cdb.keys()) == 0

        ####################################################
        # [1] Let the RP gather some provider info discovery

        # Point the RP to the OP
        self.rp["openid_relying_party"].get_context().issuer = self.op.entity_id

        # Create the URLs and messages that will be involved in this process OP -> TA
        _msgs = create_trust_chain_messages(self.op, self.ta)

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/entity-statement+jwt"},
                         status=200)

            # The client collects trust chain from the OP
            _trust_chains = get_verified_trust_chains(self.rp, self.op["federation_entity"].entity_id)

        # one would assume this
        # self.rp["openid_relying_party"].context.server_metadata = _trust_chains[0].metadata['openid_provider']
        # But NO this is what is expected
        self.rp["openid_relying_party"].context.server_metadata = _trust_chains[0].metadata
        self.rp["federation_entity"].client.context.server_metadata = _trust_chains[0].metadata

        # create trust chain client->TA. This will later be added to the Authz request
        _msgs = create_trust_chain_messages(self.rp, self.im, self.ta)
        trust_chain = [_msgs[es] for es in ['https://rp.example.org/.well-known/openid-federation',
                                            'https://im.example.org/fetch',
                                            'https://ta.example.org/fetch']]

        # create authorization request with request object
        _auth_service = self.rp["openid_relying_party"].get_service("authorization")
        authn_request = _auth_service.construct(
            request_args={"response_type": "code", "state": rndstr(), "trust_chain": trust_chain,
                          "redirect_uri":
                              self.rp["openid_relying_party"].context.claims.get_preference("redirect_uris")[0]})

        assert "request" in authn_request
        _req_args = get_payload(authn_request["request"])
        assert set(_req_args.keys()) == {'aud',
                                         'client_id',
                                         'exp',
                                         'iat',
                                         'iss',
                                         'jti',
                                         'redirect_uri',
                                         'response_type',
                                         'scope',
                                         'request'}

        # ------------------------------
        # <<<<<< On the OP's side >>>>>>>

        _msgs = create_trust_chain_messages(self.rp, self.im, self.ta)
        # _msgs = create_trust_chain_messages(self.rp)
        # add the jwks_uri
        _jwks_uri = self.rp["openid_relying_party"].get_context().get_preference("jwks_uri")
        if _jwks_uri:
            _msgs[_jwks_uri] = self.rp["openid_relying_party"].keyjar.export_jwks_as_json()

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/entity-statement+jwt"},
                         status=200)

            # The OP handles the authorization request
            _authz_endpoint = self.op["openid_provider"].get_endpoint("authorization")
            try:
                req = _authz_endpoint.parse_request(authn_request)
            except Exception as err:
                print(err)

        assert "response_type" in req
