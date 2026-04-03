import os

import pytest
import responses
from cryptojwt.jws.jws import factory
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.client.defaults import DEFAULT_OIDC_SERVICES
from idpyoidc.message.oidc import AuthorizationRequest

from fedservice.defaults import DEFAULT_OIDC_FED_SERVICES
from fedservice.entity.function import get_verified_trust_chains
from . import create_trust_chain_messages
from .build_federation import build_federation

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.join(BASE_PATH, "base_data")

TA_ID = "https://ta.example.org"
RP_ID = "https://rp.example.org"
OP_ID = "https://op.example.org"

FE_FUNCTIONS = {
    "trust_chain_collector": {
        "class": "fedservice.entity.function.trust_chain_collector.TrustChainCollector",
        "kwargs": {}
    },
    "verifier": {
        "class": "fedservice.entity.function.verifier.TrustChainVerifier",
        "kwargs": {}
    },
    "policy": {
        "class": "fedservice.entity.function.policy.TrustChainPolicy",
        "kwargs": {}
    },
    "trust_mark_verifier": {
        "class": "fedservice.entity.function.trust_mark_verifier.TrustMarkVerifier",
        "kwargs": {}
    }
}

OIDC_SERVICE = DEFAULT_OIDC_SERVICES.copy()
OIDC_SERVICE.update(DEFAULT_OIDC_FED_SERVICES)

FEDERATION_CONFIG = {
    TA_ID: {
        "entity_type": "trust_anchor",
        "subordinates": [RP_ID, OP_ID],
        "kwargs": {
            "preference": {
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.org",
                "contacts": "operations@ta.example.org",
                "scopes_supported": ["openid", "profile"],
                "response_types_supported": ['id_token', 'code', 'code id_token']
            },
            "endpoints": ["entity_configuration", "list", "fetch", "resolve"],
        }
    },
    RP_ID: {
        "entity_type": "openid_relying_party",
        "trust_anchors": [TA_ID],
        "kwargs": {
            "federation_services": ["oidc_registration", "entity_configuration",
                                    "entity_statement"],
            "authority_hints": [TA_ID],
            "services": OIDC_SERVICE,
            "entity_type_config": {
                "client_id": RP_ID,
                "client_secret": "a longesh password",
                "keys": {"key_defs": DEFAULT_KEY_DEFS},
                "preference": {
                    "grant_types": ["authorization_code", "implicit", "refresh_token"],
                    "id_token_signed_response_alg": "ES256",
                    "token_endpoint_auth_method": "client_secret_basic",
                    "token_endpoint_auth_signing_alg": "ES256",
                    "scopes_supported": ["openid", "profile"],
                    "client_registration_types": ["explicit"]
                },
            }
        }
    },
    OP_ID: {
        "entity_type": "openid_provider",
        "trust_anchors": [TA_ID],
        "kwargs": {
            "authority_hints": [TA_ID],
            "endpoints": [{
                "oidc_authz": {
                    "path": "authz",
                    'class': 'fedservice.appserver.oidc.authorization.Authorization',
                    "kwargs": {}
                }}, {
                "oidc_registration": {
                    "path": "registration",
                    'class': 'fedservice.appserver.oidc.registration.Registration',
                    "kwargs": {}
                }},
                "entity_configuration"]
        }
    }
}


class TestRpService(object):

    @pytest.fixture(autouse=True)
    def fed_setup(self):
        federation = build_federation(FEDERATION_CONFIG)
        self.ta = federation[TA_ID]
        self.rp = federation[RP_ID]
        self.op = federation[OP_ID]

        _context = self.rp["openid_relying_party"].context
        _context.issuer = self.op.entity_id
        _response_types = _context.get_preference(
            "response_types_supported", _context.supports().get("response_types_supported", [])
        )
        _context.construct_uris(_response_types)

        self.entity_config_service = self.rp["federation_entity"].get_service(
            "entity_configuration")
        self.entity_config_service.upstream_get("context").issuer = OP_ID
        self.registration_service = self.rp["federation_entity"].get_service("registration")

    def test_create_reqistration_request(self):
        # Collect information about the OP
        _msgs = create_trust_chain_messages(self.op, self.ta)

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/entity-statement+jwt"},
                         status=200)

            _trust_chains = get_verified_trust_chains(self.rp,
                                                      self.op["federation_entity"].entity_id)

        self.rp["openid_relying_party"].context.server_metadata = _trust_chains[0].metadata
        self.rp["federation_entity"].client.context.server_metadata = _trust_chains[0].metadata

        # construct the client registration request
        req_args = {"entity_id": self.rp["federation_entity"].entity_id}
        jws = self.registration_service.construct(request_args=req_args)
        assert jws

        _sc = self.registration_service.upstream_get("context")
        self.registration_service.endpoint = _sc.get_metadata_claim("federation_registration_endpoint")

        # construct the information needed to send the request
        _info = self.registration_service.get_request_parameters(request_body_type="jose", method="POST")

        assert set(_info.keys()) == {"method", "url", "body", "headers", "request"}
        assert _info["method"] == "POST"
        assert _info["url"] == "https://op.example.org/registration"
        assert _info["headers"] == {"Content-Type": "application/entity-statement+jwt"}

        _jws = _info["body"]
        _jwt = factory(_jws)
        payload = _jwt.jwt.payload()
        assert set(payload.keys()) == {"sub", "iss", "metadata", "jwks", "exp",
                                       "iat", "authority_hints"}
        assert set(payload["metadata"]["openid_relying_party"].keys()) == {
            'application_type',
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
        # Collect trust chain OP->TA
        _msgs = create_trust_chain_messages(self.op, self.ta)
        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/entity-statement+jwt"},
                         status=200)

            _trust_chains = get_verified_trust_chains(self.rp,
                                                      self.op["federation_entity"].entity_id)
        # Store it in a number of places
        self.rp["openid_relying_party"].context.server_metadata = _trust_chains[0].metadata
        self.rp["federation_entity"].client.context.server_metadata = _trust_chains[0].metadata

        _sc = self.registration_service.upstream_get("context")
        self.registration_service.endpoint = _sc.get_metadata_claim(
            "federation_registration_endpoint")

        # construct the client registration request
        _rp_fe = self.rp["federation_entity"]
        req_args = {"entity_id": _rp_fe.context.entity_id}
        jws = self.registration_service.construct(request_args=req_args)
        assert jws

        # construct the information needed to send the request
        _info = self.registration_service.get_request_parameters(
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
            resp = _reg_endp.process_request(_req)

        # >>>>>>>>>> On the RP"s side <<<<<<<<<<<<<<
        _msgs = create_trust_chain_messages(self.rp, self.ta)
        # Already has the TA EC
        del _msgs['https://ta.example.org/.well-known/openid-federation']
        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/entity-statement+jwt"},
                         status=200)

            response = self.registration_service.parse_response(resp["response_msg"], request=_info["body"])

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

        response["metadata"]["openid_relying_party"]["scope"] = "openid profile"

        self.registration_service.update_service_context(response)
        # There is a client secret
        assert self.rp["openid_relying_party"].context.claims.get_usage("client_secret")
        _keys = self.rp["openid_relying_party"].context.keyjar.get_signing_key(key_type="oct")
        assert len(_keys) == 2

        assert self.rp["openid_relying_party"].context.claims.get_usage("scope") == ["openid", "profile"]

        # Create a authorization request
        req_args = {
            "state": "ABCDE",
            "nonce": "nonce",
        }

        self.rp["openid_relying_party"].get_context().cstate.set("ABCDE", {"iss": "issuer"})

        msg = self.rp["openid_relying_party"].get_service("authorization").construct(request_args=req_args)
        assert isinstance(msg, AuthorizationRequest)

        _jws = factory(jws)
        reg_uris = _jws.jwt.payload()["metadata"]["openid_relying_party"]["redirect_uris"]
        assert msg["redirect_uri"] in reg_uris
