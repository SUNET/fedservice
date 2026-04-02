import pytest
from cryptojwt import BadSyntax
from idpyoidc.client.defaults import DEFAULT_OIDC_SERVICES
from idpyoidc.message.oauth2 import ResponseMessage

from fedservice.build_entity import FederationEntityBuilder
from fedservice.combo import FederationCombo
from fedservice.defaults import DEFAULT_OIDC_FED_SERVICES
from fedservice.defaults import LEAF_ENDPOINTS
from fedservice.entity import FederationEntity
from fedservice.appclient import ClientEntity

LEAF_ID = 'https://foodle.uninett.no'

MOD_FUNCTIONS = {
    'verifier': {
        'class': 'fedservice.entity.function.verifier.TrustChainVerifier',
        'kwargs': {}
    },
    'policy': {
        'class': 'fedservice.entity.function.policy.TrustChainPolicy',
        'kwargs': {}
    },
    'trust_mark_verifier': {
        'class': 'fedservice.entity.function.trust_mark_verifier.TrustMarkVerifier',
        'kwargs': {}
    }
}

KEY_DEFS = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "RSA", "use": ["enc"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-384", "use": ["sig"]}
]


class MockResponse(object):

    def __init__(self, status_code, text='', headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class TestClient:

    @pytest.fixture(autouse=True)
    def setup(self):
        ENT = FederationEntityBuilder(
            LEAF_ID,
            preference={
                "organization_name": "The leaf operator",
                "homepage_uri": "https://leaf.example.com",
                "contacts": "operations@leaf.example.com",
                "client_registration_types": ['explicit']
            },
            authority_hints=['https://ntnu.no']
        )
        ENT.add_services()
        ENT.add_functions(**MOD_FUNCTIONS)
        ENT.add_endpoints(**LEAF_ENDPOINTS)

        oidc_service = DEFAULT_OIDC_SERVICES.copy()
        oidc_service.update(DEFAULT_OIDC_FED_SERVICES)
        # del oidc_service['web_finger']
        config = {
            'entity_id': LEAF_ID,
            'key_conf': {'key_defs': KEY_DEFS},
            "federation_entity": {
                'class': FederationEntity,
                'kwargs': ENT.conf
            },
            "openid_relying_party": {
                'class': ClientEntity,
                'kwargs': {
                    'config': {
                        'client_id': LEAF_ID,
                        'client_secret': 'a longesh password',
                        'redirect_uris': ['https://example.com/cli/authz_cb'],
                        "keys": {"uri_path": "static/jwks.json", "key_defs": KEY_DEFS},
                        "grant_types": ['authorization_code', 'implicit', 'refresh_token'],
                        "id_token_signed_response_alg": "ES256",
                        "token_endpoint_auth_method": "client_secret_basic",
                        "client_registration_types": ['automatic']
                    },
                    "services": oidc_service
                }
            },
        }

        self.entity = FederationCombo(config=config)
        self.rp = self.entity['openid_relying_party']

    def test_parse_error(self):
        _resp = MockResponse(
            status_code=200,
            text='Some information',
            headers={
                'content-type': 'text/plain'
            }
        )

        with pytest.raises(BadSyntax):
            self.rp.parse_request_response(self.rp.get_service('registration'), _resp)

    def test_redirect(self):
        _resp = MockResponse(
            status_code=302,
            text='Some information',
            headers={
                'content-type': 'text/plain'
            }
        )

        _parse_resp = self.rp.parse_request_response(self.rp.get_service('registration'), _resp)
        assert _parse_resp == _resp

    def test_500_error(self):
        _resp = MockResponse(
            status_code=500,
            text='Serious error',
            headers={
                'content-type': 'text/plain'
            }
        )

        with pytest.raises(SystemError):
            self.rp.parse_request_response(self.rp.get_service('registration'), _resp)

    def test_404_error(self):
        msg = ResponseMessage(error='page missing')

        # JSON
        _resp = MockResponse(
            status_code=404,
            text=msg.to_json(),
            headers={'content-type': 'application/json'}
        )

        err_resp = self.rp.parse_request_response(self.rp.get_service('registration'), _resp)
        assert err_resp

        # URLENCODED
        _resp = MockResponse(
            status_code=404,
            text=msg.to_urlencoded(),
            headers={'content-type': "application/x-www-form-urlencoded"}
        )

        err_resp = self.rp.parse_request_response(self.rp.get_service('registration'), _resp)
        assert err_resp

        # Wrongly marked
        _resp = MockResponse(
            status_code=404,
            text=msg.to_urlencoded(),
            headers={'content-type': "application/json"}
        )

        err_resp = self.rp.parse_request_response(self.rp.get_service('registration'), _resp)
        assert err_resp
