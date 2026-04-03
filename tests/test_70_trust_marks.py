import os

import pytest
import responses
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.key_import import import_jwks
from idpyoidc.message import Message

from fedservice.defaults import LEAF_ENDPOINTS
from fedservice.entity.function import get_verified_trust_chains
from fedservice.message import TrustMark
from fedservice.utils import make_federation_entity
from tests import create_trust_chain_messages

TA_ENDPOINTS = ["list", "fetch", "entity_configuration"]

TA_ID = "https://ta.example.org"
TMI_ID = "https://tmi.example.org"
FE_ID = "https://entity.example.org"

TRUST_MARK_TYPE = "https://example.com/trust_mark"

BASE_PATH = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASE_PATH, local_file)


def get_client_info(client_id, endpoint):
    trust_chains = get_verified_trust_chains(endpoint, client_id)
    if trust_chains:
        _context = endpoint.upstream_get("context")
        _context.trust_chain_cache[client_id] = trust_chains
        return trust_chains[0].metadata["federation_entity"]
    else:
        return {}


class TestTrustMarkEndpoints():

    @pytest.fixture(autouse=True)
    def setup(self):
        # start from scratch every time
        if os.path.exists(full_path("trust_mark")):
            os.unlink(full_path("trust_mark"))

        self.ta = make_federation_entity(
            TA_ID,
            preference={
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.com",
                "contacts": "operations@ta.example.com",
                "trust_mark_issuers": {
                    TRUST_MARK_TYPE: TMI_ID
                }
            },
            key_config={"key_defs": DEFAULT_KEY_DEFS},
            endpoints=TA_ENDPOINTS
        )

        ANCHOR = {self.ta.entity_id: self.ta.keyjar.export_jwks()}

        # Federation entity with trust mark endpoints
        self.trust_mark_issuer = make_federation_entity(
            TMI_ID,
            preference={
                "organization_name": "Trust Mark Issuer 'R US"
            },
            key_config={"key_defs": DEFAULT_KEY_DEFS},
            authority_hints=[TA_ID],
            endpoints=["entity_configuration"],
            trust_anchors=ANCHOR,
            trust_mark_entity={
                "class": "fedservice.trust_mark_entity.entity.TrustMarkEntity",
                "kwargs": {
                    "trust_mark_specification": {
                        TRUST_MARK_TYPE: {"lifetime": 2592000}
                    },
                    "trust_mark_db": {
                        "class": "fedservice.trust_mark_entity.FileDB",
                        "kwargs": {TRUST_MARK_TYPE: full_path("trust_mark")}
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
                            "class": "fedservice.trust_mark_entity.server.trust_mark_list.TrustMarkList",
                            "kwargs": {}
                        },
                        "trust_mark_status": {
                            "path": "trust_mark_status",
                            "class": "fedservice.trust_mark_entity.server.trust_mark_status.TrustMarkStatus",
                            "kwargs": {}
                        }
                    }
                }
            }
        )

        self.ta.server.subordinate[TMI_ID] = {
            "jwks": self.trust_mark_issuer.keyjar.export_jwks(),
            'authority_hints': [TA_ID]
        }

        self.federation_entity = make_federation_entity(
            FE_ID,
            preference={
                "homepage_uri": "https://rp.example.com",
                "contacts": "operations@rp.example.com"
            },
            key_config={"key_defs": DEFAULT_KEY_DEFS},
            authority_hints=[TA_ID],
            endpoints=LEAF_ENDPOINTS,
            trust_anchors=ANCHOR,
            services={
                'entity_configuration': {
                    'class': 'fedservice.entity.client.entity_configuration.EntityConfiguration',
                    'kwargs': {}},
                'trust_mark_list': {
                    'class': "fedservice.entity.client.trust_mark_list.TrustMarkList"
                },
                'trust_mark': {
                    'class': "fedservice.entity.client.trust_mark.TrustMark",
                    "kwargs": {"default_authn_method": "private_key_jwt"}
                },
                'trust_mark_status': {
                    'class': "fedservice.entity.client.trust_mark_status.TrustMarkStatus"
                }
            }
        )

        self.ta.server.subordinate[FE_ID] = {
            "jwks": self.federation_entity.keyjar.export_jwks(),
            'authority_hints': [FE_ID]
        }

    def test_list_trust_marks_empty(self):
        _client_service = self.federation_entity.get_service("trust_mark_list")
        _server_endpoint = self.trust_mark_issuer.get_endpoint("trust_mark_list")

        req_info = _client_service.get_request_parameters(request_args={"trust_mark_type": TRUST_MARK_TYPE},
                                                          fetch_endpoint=_server_endpoint.full_path)

        _query = req_info["url"].split("?")[1]
        _req = Message().from_urlencoded(_query)
        _parse_req = _server_endpoint.parse_request(_req.to_dict())
        _hw_resp = _server_endpoint.process_request(_parse_req)
        _resp = _server_endpoint.do_response(**_hw_resp)
        assert set(_resp.keys()) == {"response", "http_headers"}
        assert _resp["response"] == []

    def test_get_trust_mark(self):
        self.federation_entity.client.context.issuer = self.trust_mark_issuer.entity_id

        _server_endpoint = self.trust_mark_issuer.get_endpoint("trust_mark")
        _client_service = self.federation_entity.get_service("trust_mark")
        _audience = _server_endpoint.full_path

        req_info = _client_service.get_request_parameters(
            request_args={"trust_mark_type": TRUST_MARK_TYPE, "sub": self.federation_entity.entity_id},
            endpoint=_audience,
            audience=_audience,
            algorithm="ES256")

        _client_jwks = _client_service.upstream_get("attribute", "keyjar").export_jwks()
        _kj = _server_endpoint.upstream_get("attribute", "keyjar")
        _kj = import_jwks(_kj, _client_jwks, self.federation_entity.entity_id)
        _query = req_info["url"].split("?")[1]
        _req = Message().from_urlencoded(_query)

        _msgs = create_trust_chain_messages(self.federation_entity, self.ta)

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            _parse_req = _server_endpoint.parse_request(_req.to_dict(), get_client_info=get_client_info)

        _hw_resp = _server_endpoint.process_request(_parse_req)
        _resp = _server_endpoint.do_response(response_args=_hw_resp)
        assert set(_resp.keys()) == {"response", "http_headers"}

        # Check the signed JWT
        _tm = TrustMark().from_jwt(_resp["response"], keyjar=_kj)
        _tm.verify()
        assert set(_tm.keys()) == {'iat', 'trust_mark_type', 'sub', 'exp', 'iss'}

        # should be one item in the list
        _client_service = self.federation_entity.get_service("trust_mark_list")
        req_info = _client_service.get_request_parameters(request_args={"trust_mark_type": TRUST_MARK_TYPE},
                                                          fetch_endpoint=f"{self.trust_mark_issuer.entity_id}/trust_mark_list")

        _server_endpoint = self.trust_mark_issuer.get_endpoint("trust_mark_list")
        _query = req_info["url"].split("?")[1]
        _req = Message().from_urlencoded(_query)
        _parse_resp = _server_endpoint.parse_request(_req.to_dict())
        _hw_resp = _server_endpoint.process_request(_parse_resp)
        assert "response_msg" in _hw_resp
        assert _hw_resp["response_msg"] == '["https://entity.example.org"]'

        # Status should be OK
        _client_service = self.federation_entity.get_service("trust_mark_status")
        _server_endpoint = self.trust_mark_issuer.get_endpoint("trust_mark_status")

    def test_create_metadata(self):
        _metadata = self.trust_mark_issuer.get_metadata()
        assert set(_metadata.keys()) == {"federation_entity"}
        assert set(_metadata["federation_entity"].keys()) == {'federation_trust_mark_endpoint',
                                                              'federation_trust_mark_list_endpoint',
                                                              'federation_trust_mark_status_endpoint',
                                                              'federation_trust_mark_endpoint_auth_methods',
                                                              'federation_trust_mark_list_endpoint_auth_methods',
                                                              'federation_trust_mark_status_endpoint_auth_methods',
                                                              'organization_name'}
        fe_metadata = _metadata["federation_entity"]
        assert fe_metadata["federation_trust_mark_endpoint_auth_methods"] == ["private_key_jwt"]
        assert fe_metadata["federation_trust_mark_list_endpoint_auth_methods"] == ["none"]
        assert fe_metadata["federation_trust_mark_status_endpoint_auth_methods"] == ["none"]