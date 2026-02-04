import os

import pytest
import responses
from cryptojwt.jws.jws import factory
from idpyoidc.message.oidc import AuthorizationRequest

from fedservice.entity.function import get_verified_trust_chains
from . import create_trust_chain_messages
from .build_federation import build_federation

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.join(BASE_PATH, "base_data")

from .federation_example import TA_OP_RP


class TestRpService(object):

    @pytest.fixture(autouse=True)
    def fed_setup(self):
        federation = build_federation(TA_OP_RP.FEDERATION_CONFIG)
        self.ta = federation[TA_OP_RP.TA_ID]
        self.rp = federation[TA_OP_RP.RP_ID]
        self.op = federation[TA_OP_RP.OP_ID]

        _context = self.rp["openid_relying_party"].context['']
        _context.issuer = self.op['federation_entity'].context.entity_id
        _response_types = _context.get_preference(
            "response_types_supported", _context.supports().get("response_types_supported", [])
        )
        _context.construct_uris(_response_types)

        self.entity_config_service = self.rp["federation_entity"].get_service(
            "entity_configuration")
        self.entity_config_service.upstream_get("context").issuer = TA_OP_RP.OP_ID
        self.registration_service = self.rp["federation_entity"].get_service("registration")

    def test_create_reqistration_request(self):
        # Start with creating a sever specific context

        server_entity_id = self.op.entity_id
        spec_context = self.rp['openid_relying_party'].add_new_context(server_entity_id=self.op.entity_id)

        # Collect information about the OP
        _msgs = create_trust_chain_messages(self.op, self.ta)

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/entity-statement+jwt"},
                         status=200)

            _trust_chains = get_verified_trust_chains(self.rp,
                                                      self.op["federation_entity"].context.entity_id)

        self.rp["openid_relying_party"].context[server_entity_id].server_metadata = _trust_chains[0].metadata
        _fe_context = self.rp["federation_entity"].client.context
        _fe_context.server_metadata = _trust_chains[0].metadata

        # construct the client registration request
        req_args = {"entity_id": _fe_context.entity_id}
        jws = self.registration_service.construct(_fe_context, request_args=req_args)
        assert jws

        _sc = self.registration_service.upstream_get("context", server_entity_id)
        self.registration_service.endpoint = _sc.get_metadata_claim("federation_registration_endpoint")

        # construct the information needed to send the request
        _info = self.registration_service.get_request_parameters(_fe_context, request_body_type="jose", method="POST")

        assert set(_info.keys()) == {"method", "url", "body", "headers", "request"}
        assert _info["method"] == "POST"
        assert _info["url"] == "https://op.example.org/registration"
        assert _info["headers"] == {"Content-Type": 'application/explicit-registration-response+jwt'}

        _jws = _info["body"]
        _jwt = factory(_jws)
        payload = _jwt.jwt.payload()
        assert set(payload.keys()) == {"sub", "iss", "metadata", "jwks", "exp",
                                       "iat", "authority_hints"}
        assert set(payload["metadata"]["openid_relying_party"].keys()) == {'application_type',
                                                                           'client_registration_types',
                                                                           'default_max_age',
                                                                           'grant_types',
                                                                           'id_token_signed_response_alg',
                                                                           'jwks',
                                                                           'redirect_uris',
                                                                           'request_object_signing_alg',
                                                                           'response_modes',
                                                                           'response_types',
                                                                           'subject_type',
                                                                           'token_endpoint_auth_method',
                                                                           'token_endpoint_auth_signing_alg',
                                                                           'userinfo_signed_response_alg'}

    def test_parse_registration_response(self):
        # Start with creating a sever specific context

        server_entity_id = self.op.entity_id
        rp_context = self.rp['openid_relying_party'].add_new_context(server_entity_id=self.op.entity_id)

        # Collect trust chain OP->TA
        _msgs = create_trust_chain_messages(self.op, self.ta)
        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/entity-statement+jwt"},
                         status=200)

            _trust_chains = get_verified_trust_chains(self.rp, server_entity_id)
        # Store it in a number of places
        rp_context.server_metadata = _trust_chains[0].metadata
        rp_context.provider_info = _trust_chains[0].metadata['openid_provider']
        _fe_context = self.rp["federation_entity"].client.context
        _fe_context.server_metadata = _trust_chains[0].metadata

        _sc = self.registration_service.upstream_get("context", server_entity_id)
        self.registration_service.endpoint = _sc.get_metadata_claim(
            "federation_registration_endpoint")

        # construct the client registration request
        _rp_fe = self.rp["federation_entity"]
        req_args = {"entity_id": _rp_fe.context.entity_id}
        jws = self.registration_service.construct(_fe_context, request_args=req_args)
        assert jws

        # construct the information needed to send the request
        _info = self.registration_service.get_request_parameters(
            _fe_context, request_body_type="jose", method="POST")

        # >>>>> The OP as federation entity <<<<<<<<<<

        _reg_endp = self.op["openid_provider"].get_endpoint("registration")

        # Collect trust chain for RP->TA
        _msgs = create_trust_chain_messages(self.rp, self.ta)
        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/entity-statement+jwt"},
                         status=200)

            _req = _reg_endp.parse_request(_info["request"])
            resp = _reg_endp.process_request(_req)

        # >>>>>>>>>> On the RP's side <<<<<<<<<<<<<<
        _msgs = create_trust_chain_messages(self.rp, self.ta)
        # Already has the TA EC
        del _msgs['https://ta.example.org/.well-known/openid-federation']
        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/entity-statement+jwt"},
                         status=200)

            response = self.registration_service.parse_response(rp_context, resp["response_msg"], request=_info["body"])

        metadata = response["metadata"]
        # The response doesn't touch the federation_entity metadata, therefor it's not included
        assert set(metadata.keys()) == {'openid_relying_party'}

        assert set(metadata["openid_relying_party"].keys()) == {'application_type',
                                                                'client_id',
                                                                'client_id_issued_at',
                                                                'client_registration_types',
                                                                'client_secret',
                                                                'client_secret_expires_at',
                                                                'default_max_age',
                                                                'grant_types',
                                                                'id_token_signed_response_alg',
                                                                'jwks',
                                                                'redirect_uris',
                                                                'request_object_signing_alg',
                                                                'response_modes',
                                                                'response_types',
                                                                'subject_type',
                                                                'token_endpoint_auth_method',
                                                                'token_endpoint_auth_signing_alg',
                                                                'userinfo_signed_response_alg'}

        # response["metadata"]["openid_relying_party"]["scope"] = "openid profile"

        self.registration_service.update_service_context(rp_context, response)
        # There is a no client secret
        _context = self.rp["openid_relying_party"].context[server_entity_id]
        assert _context.claims.get_usage("client_secret")
        _keys = _context.keyjar.get_signing_key(key_type="oct")
        assert len(_keys) == 1

        assert _context.claims.get_usage("scope") == ["openid", "profile"]

        # Create an authorization request
        req_args = {
            "state": "ABCDE",
            "nonce": "nonce",
        }

        _context.cstate.set("ABCDE", {"iss": "issuer"})

        msg = self.rp["openid_relying_party"].get_service(_context, "authorization").construct(_context,
                                                                                               request_args=req_args)
        assert isinstance(msg, AuthorizationRequest)

        _jws = factory(jws)
        reg_uris = _jws.jwt.payload()["metadata"]["openid_relying_party"]["redirect_uris"]
        assert msg["redirect_uri"] in reg_uris

    def test_parse_registration_response_wrong_jwt_type(self):
        server_entity_id = self.op.entity_id
        rp_context = self.rp['openid_relying_party'].add_new_context(server_entity_id=server_entity_id)

        # Collect trust chain OP->TA
        _msgs = create_trust_chain_messages(self.op, self.ta)
        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/entity-statement+jwt"},
                         status=200)

            _trust_chains = get_verified_trust_chains(self.rp,
                                                      self.op["federation_entity"].context.entity_id)
        # Store it in a number of places
        rp_context.server_metadata = _trust_chains[0].metadata
        self.rp["federation_entity"].client.context.server_metadata = _trust_chains[0].metadata

        _sc = self.registration_service.upstream_get("context")
        self.registration_service.endpoint = _sc.get_metadata_claim(
            "federation_registration_endpoint")

        # construct the client registration request
        _rp_fe = self.rp["federation_entity"]
        req_args = {"entity_id": _rp_fe.context.entity_id}
        jws = self.registration_service.construct(_rp_fe.client.context, request_args=req_args)
        assert jws

        # construct the information needed to send the request
        _info = self.registration_service.get_request_parameters(_rp_fe.client.context,
                                                                 request_body_type="jose", method="POST")

        # >>>>> The OP as federation entity <<<<<<<<<<

        _reg_endp = self.op["openid_provider"].get_endpoint("registration")

        # Collect trust chain for RP->TA
        _msgs = create_trust_chain_messages(self.rp, self.ta)
        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/entity-statement+jwt"},
                         status=200)

            _req = _reg_endp.parse_request(_info["request"])
            # Set the JWT type to something faulty
            _reg_endp.payload_type = "foobar+jwt"
            resp = _reg_endp.process_request(_req)

        # >>>>>>>>>> On the RP's side <<<<<<<<<<<<<<
        # Wrong JWT type
        with pytest.raises(ValueError):
            self.registration_service.parse_response(rp_context, resp["response_msg"], request=_info["body"])
