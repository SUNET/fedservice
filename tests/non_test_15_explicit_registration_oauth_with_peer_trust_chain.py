import os

import pytest
import responses
from cryptojwt import JWT
from cryptojwt.jws.jws import factory
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS

from fedservice.defaults import DEFAULT_OAUTH2_FED_SERVICES
from fedservice.defaults import federation_services
from fedservice.defaults import OAUTH2_FED_ENDPOINTS
from fedservice.entity.function import get_verified_trust_chains
from fedservice.entity.function import verify_trust_chain
from fedservice.message import ExplicitRegistrationResponse
from . import create_trust_chain_messages
from .build_federation import build_federation

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.join(BASE_PATH, "base_data")

TA_ID = "https://ta.example.org"
RP_ID = "https://rp.example.org"
AS_ID = "https://op.example.org"

OAUTH_SERVICE = DEFAULT_OAUTH2_FED_SERVICES
OAUTH_FED_SERVICE = federation_services('entity_configuration', "entity_statement")

FEDERATION_CONFIG = {
    TA_ID: {
        "federation_entity": {
            "subordinates": [RP_ID, AS_ID],
            "preference": {
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.org",
                "contacts": "operations@ta.example.org"
            },
            "endpoint": ["entity_configuration", "list", "fetch", "resolve"],
        }
    },
    RP_ID: {
        "federation_entity": {
            "trust_anchors": [TA_ID],
            "authority_hints": [TA_ID],
            "services": ['entity_configuration', "entity_statement"],
        },
        "oauth_client": {
            "services": OAUTH_SERVICE,
            "client_id": RP_ID,
            "client_secret": "a longesh password",
            "redirect_uris": ["https://example.com/cli/authz_cb"],
            "keys": {"key_defs": DEFAULT_KEY_DEFS},
            "preference": {
                "grant_types": ["authorization_code", "implicit", "refresh_token"],
                "token_endpoint_auth_method": "client_secret_basic",
                "token_endpoint_auth_signing_alg": "ES256"
            }
        }
    },
    AS_ID: {
        "federation_entity": {
            "trust_anchors": [TA_ID],
            "authority_hints": [TA_ID],
            'endpoint': ['entity_configuration', 'fetch']
        },
        "oauth_authorization_server": {
            "endpoint": OAUTH2_SERVER_ENDPOINTS
        }
    }
}

class TestRpService(object):

    @pytest.fixture(autouse=True)
    def rp_setup(self):
        federation = build_federation(FEDERATION_CONFIG)
        self.ta = federation[TA_ID]
        self.rp = federation[RP_ID]
        self.oas = federation[AS_ID]

        self.registration_service = self.rp["oauth_client"].get_service("registration")

    def create_trust_chains(self):
        # Collect information about the OP
        _msgs = create_trust_chain_messages(self.oas, self.ta)

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/entity-statement+jwt"},
                         status=200)

            _trust_chains = get_verified_trust_chains(self.rp,
                                                      self.oas["federation_entity"].entity_id)

        self.rp["oauth_client"].context.server_metadata = _trust_chains[0].metadata
        self.rp["federation_entity"].client.context.server_metadata = _trust_chains[0].metadata

        peer_trust_chain = _trust_chains[0].chain[:]
        peer_trust_chain.reverse()

        _msgs = create_trust_chain_messages(self.rp, self.ta)
        del _msgs['https://ta.example.org/.well-known/openid-federation']

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/entity-statement+jwt"},
                         status=200)

            _trust_chains = get_verified_trust_chains(self.rp,
                                                      self.rp["federation_entity"].entity_id)

        trust_chain = _trust_chains[0].chain[:]
        trust_chain.reverse()

        return trust_chain, peer_trust_chain

    def test_create_reqistration_request(self):
        trust_chain, peer_trust_chain = self.create_trust_chains()

        # construct the client registration request
        req_args = {"entity_id": self.rp["federation_entity"].entity_id,
                    'aud': self.oas.entity_id}

        _sc = self.registration_service.upstream_get("context")
        self.registration_service.endpoint = _sc.get_metadata_claim(
            "federation_registration_endpoint")

        # construct the information needed to send the request
        _info = self.registration_service.get_request_parameters(
            request_args=req_args,
            request_body_type="jose", method="POST",
            behaviour_args={
                "client": self.rp["oauth_client"],
                "peer_trust_chain": peer_trust_chain,
                'trust_chain': trust_chain,
            })

        assert set(_info.keys()) == {"method", "url", "body", "headers", "request"}
        assert _info["method"] == "POST"
        assert _info["url"] == "https://op.example.org/registration"
        assert _info["headers"] == {"Content-Type": 'application/entity-statement+jwt'}

        _jws = _info["body"]
        _jwt = factory(_jws)
        payload = _jwt.jwt.payload()
        assert set(payload.keys()) == {"sub", "iss", "metadata", "jwks", "exp", 'aud',
                                       "iat", "authority_hints"}
        assert set(payload["metadata"]["oauth_client"].keys()) == {
            'redirect_uris', 'jwks', 'response_types', 'token_endpoint_auth_method'}

        assert 'peer_trust_chain' in _jwt.jwt.headers
        assert 'trust_chain' in _jwt.jwt.headers
        # verify that both peer_trust_chain and trust_chain are valid and ends in the same TA

        _tc = verify_trust_chain(self.oas, trust_chain)[0]
        _ptc = verify_trust_chain(self.oas, peer_trust_chain)[0]

        assert _tc.anchor == _ptc.anchor

    def test_parse_registration_request(self):
        # Collect trust chain OP->TA

        trust_chain, peer_trust_chain = self.create_trust_chains()

        _sc = self.registration_service.upstream_get("context")
        self.registration_service.endpoint = _sc.get_metadata_claim(
            "federation_registration_endpoint")

        # construct the client registration request
        _rp_fe = self.rp["federation_entity"]
        req_args = {"entity_id": _rp_fe.entity_id,
                    'aud': self.oas.entity_id}

        # construct the information needed to send the request
        _info = self.registration_service.get_request_parameters(
            request_args=req_args,
            request_body_type="jose",
            method="POST",
            behaviour_args={
                "client": self.rp["oauth_client"],
                "peer_trust_chain": peer_trust_chain,
                'trust_chain': trust_chain
            })

        # >>>>> The OP as federation entity <<<<<<<<<<

        _reg_endp = self.oas["oauth_authorization_server"].get_endpoint("registration")
        _req = _reg_endp.parse_request(_info["request"])
        resp = _reg_endp.process_request(_req)

        keyjar = self.oas['federation_entity'].keyjar
        _jwt = JWT(key_jar=keyjar, allowed_sign_algs=["RS256"])
        _jwt.msg_cls = ExplicitRegistrationResponse
        _err = _jwt.unpack(resp['response_msg'])
        _err.verify()

        assert _err['aud'][0] == self.rp.entity_id
        assert _err['trust_anchor'] == self.ta.entity_id

        # # >>>>>>>>>> On the RP"s side <<<<<<<<<<<<<<
        # _msgs = create_trust_chain_messages(self.rp, self.ta)
        # # Already have this EC
        # del _msgs['https://ta.example.org/.well-known/openid-federation']
        #
        # with responses.RequestsMock() as rsps:
        #     for _url, _jwks in _msgs.items():
        #         rsps.add("GET", _url, body=_jwks,
        #                  adding_headers={"Content-Type": "application/entity-statement+jwt"},
        #                  status=200)
        #
        #     response = self.registration_service.parse_response(resp["response_msg"],
        #                                                         request=_info["body"],
        #                                                         sub=sub)
        #
        # metadata = response["metadata"]
        # # The response doesn't touch the federation_entity metadata, therefor it's not included
        # assert set(metadata.keys()) == {'oauth_client'}
        #
        # assert set(metadata["oauth_client"].keys()) == {'client_id',
        #                                                 'client_id_issued_at',
        #                                                 'client_secret',
        #                                                 'client_secret_expires_at',
        #                                                 'jwks',
        #                                                 'redirect_uris',
        #                                                 'response_types',
        #                                                 'token_endpoint_auth_method'}
