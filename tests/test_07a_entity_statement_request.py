import os
from urllib.parse import parse_qs
from urllib.parse import urlparse

import pytest
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS

from fedservice.defaults import COMBINED_DEFAULT_OAUTH2_SERVICES
from fedservice.defaults import DEFAULT_OAUTH2_FED_SERVICES
from fedservice.defaults import federation_endpoints
from fedservice.defaults import federation_services
from fedservice.entity.utils import get_federation_entity
from fedservice.message import SubordinateStatement
from tests import CRYPT_CONFIG
from tests.build_federation import build_federation

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.join(BASE_PATH, "base_data")

TA_ID = "https://ta.example.org"
OC_ID = "https://client.example.org"
IM_ID = "https://im.example.org"

SESSION_PARAMS = {"encrypter": CRYPT_CONFIG}

OC_SERVICES = federation_services("entity_configuration", "entity_statement")
# OC_SERVICES.update(DEFAULT_OAUTH2_FED_SERVICES)

AS_SERVICES = federation_services("entity_configuration", "entity_statement")
AS_SERVICES.update(DEFAULT_OAUTH2_FED_SERVICES)

AS_ENDPOINTS = federation_endpoints("entity_configuration", "fetch")

FEDERATION_CONFIG = {
    TA_ID: {
        "federation_entity": {
            "subordinate": [IM_ID],
            "preference": {
                "organization_name": "The example federation operator",
                "organization_uri": "https://ta.example.org",
                "contacts": "operations@ta.example.org"
            },
            "endpoint": ["entity_configuration", "list", "fetch", "resolve"],
            'key_config': {"key_defs": DEFAULT_KEY_DEFS},
        }
    },
    OC_ID: {
        "federation_entity": {
            "trust_anchors": [TA_ID],
            "services": OC_SERVICES,
            "authority_hints": [IM_ID],
            'key_config': {"key_defs": DEFAULT_KEY_DEFS},
        },
        "oauth_client": {
            "services": COMBINED_DEFAULT_OAUTH2_SERVICES,
            "key_config": {"key_defs": DEFAULT_KEY_DEFS},
            "base_url": OC_ID,
            "client_id": OC_ID,
            "client_secret": "a longeeesh password",
            "redirect_uris": ["https://rp.example.com/cli/authz_cb"],
            "preference": {
                "grant_types": ["authorization_code", "implicit", "refresh_token"],
                "id_token_signed_response_alg": "ES256",
                "token_endpoint_auth_method": "client_secret_basic",
                "token_endpoint_auth_signing_alg": "ES256",
                "request_parameter_supported": True
            },
            "authorization_request_endpoints": [
                "authorization_endpoint", "pushed_authorization_request_endpoint"
            ]
        },
    },
    IM_ID: {
        "federation_entity": {
            "trust_anchors": [TA_ID],
            "subordinate": [OC_ID],
            "authority_hints": [TA_ID],
            'key_config': {"key_defs": DEFAULT_KEY_DEFS},
        }
    }
}


class TestFederationStatement(object):

    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        #              TA
        #          +---|---+
        #          |       |
        #          IM     OAS
        #          |
        #          OC

        federation = build_federation(FEDERATION_CONFIG)
        self.ta = federation[TA_ID]
        self.oc = federation[OC_ID]
        self.im = federation[IM_ID]

    def test_entity_configuration(self):
        _service = self.oc["federation_entity"].get_service("entity_configuration")

        args = _service.get_request_parameters(issuer=TA_ID)
        assert set(args.keys()) == {"url", "method"}
        assert args["method"] == "GET"
        assert args["url"] == 'https://ta.example.org/.well-known/openid-federation'

    def test_subordinate_statement(self):
        _service = self.oc["federation_entity"].get_service("entity_configuration")

        args = _service.get_request_parameters(issuer=TA_ID)

        _endpoint = get_federation_entity(self.ta).server.get_endpoint('entity_configuration')
        _context = _endpoint.upstream_get("context")
        _entcnf = _endpoint.process_request({})["response"]
        response = _service.parse_response(_context, _entcnf)

        #  .......
        _service = self.oc["federation_entity"].get_service("entity_statement")
        args = _service.get_request_parameters(issuer=TA_ID, subject=IM_ID)
        assert set(args.keys()) == {"url", "method"}
        assert args["method"] == "GET"
        assert args["url"] == 'https://ta.example.org/fetch?sub=https%3A%2F%2Fim.example.org'

        _endpoint = get_federation_entity(self.ta).server.get_endpoint('fetch')
        parse_res = urlparse(args.get("url"))
        args = {k: v[0] for k, v in parse_qs(parse_res.query).items()}
        _response = _endpoint.process_request(args)

        resp = _service.parse_response(_service.upstream_get("context"), _response['response_msg'])
        assert isinstance(resp, SubordinateStatement)
        assert resp['sub'] == 'https://im.example.org'
        assert resp['iss'] == 'https://ta.example.org'

    def test_2(self):
        _service = self.oc["federation_entity"].get_service("entity_statement")
        _endpoint = get_federation_entity(self.ta).server.get_endpoint('entity_configuration')
        _entcnf = _endpoint.process_request({})["response"]

        args = _service.get_request_parameters(issuer=TA_ID, subject=IM_ID,
                                               fetch_endpoint="https://ta.example.org/fetch")
        assert set(args.keys()) == {"url", "method"}
        assert args["method"] == "GET"
        assert args["url"] == 'https://ta.example.org/fetch?sub=https%3A%2F%2Fim.example.org'
