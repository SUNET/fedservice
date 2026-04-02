import os

import pytest
import responses
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS

from fedservice.defaults import COMBINED_DEFAULT_OAUTH2_SERVICES
from fedservice.defaults import DEFAULT_OAUTH2_FED_SERVICES
from fedservice.defaults import federation_endpoints
from fedservice.defaults import federation_services
from fedservice.entity.utils import get_federation_entity
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
        "entity_type": "trust_anchor",
        "subordinates": [IM_ID],
        "kwargs": {
            "preference": {
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.org",
                "contacts": "operations@ta.example.org"
            },
            "endpoints": ["entity_configuration", "list", "fetch", "resolve"],
        }
    },
    OC_ID: {
        "entity_type": "oauth_client",
        "trust_anchors": [TA_ID],
        "services": OC_SERVICES,
        "kwargs": {
            "authority_hints": [IM_ID],
            "services": COMBINED_DEFAULT_OAUTH2_SERVICES,
            "entity_type_config": {
                # OAuth2 core keys
                "keys": {"key_defs": DEFAULT_KEY_DEFS},
                "base_url": OC_ID,
                "client_id": OC_ID,
                "client_secret": "a longeeesh password",
                "redirect_uris": ["https://rp.example.com/cli/authz_cb"],
                "preference": {
                    "grant_types": ["authorization_code", "implicit", "refresh_token"],
                    "id_token_signed_response_alg": "ES256",
                    "token_endpoint_auth_method": "client_secret_basic",
                    "token_endpoint_auth_signing_alg": "ES256",
                    "client_registration_types": ["automatic"],
                    "request_parameter_supported": True
                },
                "authorization_request_endpoints": [
                    "authorization_endpoint", "pushed_authorization_request_endpoint"
                ]
            }
        }
    },
    IM_ID: {
        "entity_type": "federation_entity",
        "trust_anchors": [TA_ID],
        "subordinates": [OC_ID],
        "kwargs": {
            "authority_hints": [TA_ID]
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

    def test_1(self):
        _service = self.oc["federation_entity"].get_service("entity_statement")
        _endpoint = get_federation_entity(self.ta).server.get_endpoint('entity_configuration')
        _entcnf = _endpoint.process_request({})["response"]

        with responses.RequestsMock() as rsps:
            rsps.add("GET", _endpoint.full_path, body=_entcnf,
                     adding_headers={"Content-Type": "application/json"}, status=200)

            args = _service.get_request_parameters(issuer=TA_ID, subject=IM_ID)
        assert set(args.keys()) == {"url", "method"}
        assert args["method"] == "GET"
        assert args["url"] == 'https://ta.example.org/fetch?sub=https%3A%2F%2Fim.example.org'

    def test_2(self):
        _service = self.oc["federation_entity"].get_service("entity_statement")
        _endpoint = get_federation_entity(self.ta).server.get_endpoint('entity_configuration')
        _entcnf = _endpoint.process_request({})["response"]

        args = _service.get_request_parameters(issuer=TA_ID, subject=IM_ID,
                                               fetch_endpoint="https://ta.example.org/fetch")
        assert set(args.keys()) == {"url", "method"}
        assert args["method"] == "GET"
        assert args["url"] == 'https://ta.example.org/fetch?sub=https%3A%2F%2Fim.example.org'
