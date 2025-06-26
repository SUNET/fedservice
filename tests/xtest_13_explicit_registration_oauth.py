import os

import pytest
import responses
from cryptojwt.jws.jws import factory
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.client.defaults import DEFAULT_OAUTH2_SERVICES

from fedservice.appclient import ClientEntity
from fedservice.appserver import ServerEntity
from fedservice.defaults import DEFAULT_FEDERATION_ENTITY_ENDPOINTS
from fedservice.defaults import DEFAULT_OAUTH2_FED_SERVICES
from fedservice.defaults import LEAF_ENDPOINTS
from fedservice.defaults import WELL_KNOWN_FEDERATION_ENDPOINT
from fedservice.utils import make_federation_combo
from fedservice.utils import make_federation_entity
from . import create_trust_chain_messages
from . import CRYPT_CONFIG

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.join(BASE_PATH, 'base_data')

TA_ID = "https://ta.example.org"
RP_ID = "https://rp.example.org"
OP_ID = "https://op.example.org"
IM_ID = "https://im.example.org"

TA_ENDPOINTS = DEFAULT_FEDERATION_ENTITY_ENDPOINTS.copy()

RESPONSE_TYPES_SUPPORTED = [
    ["code"],
    ["token"],
    ["id_token"],
    ["code", "token"],
    ["code", "id_token"],
    ["id_token", "token"],
    ["code", "token", "id_token"],
    ["none"],
]

SESSION_PARAMS = {"encrypter": CRYPT_CONFIG}


class TestExplicit(object):

    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        #              TA
        #          +---|---+
        #          |       |
        #          IM      OP
        #          |
        #          RP

        ########################################
        # TRUST ANCHOR
        ########################################

        self.ta = make_federation_entity(
            TA_ID,
            preference={
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.com",
                "contacts": "operations@ta.example.com"
            },
            key_config={"key_defs": DEFAULT_KEY_DEFS}
        )

        ANCHOR = {TA_ID: self.ta.keyjar.export_jwks()}

        ########################################
        # intermediate
        ########################################

        self.im = make_federation_entity(
            IM_ID,
            preference={
                "organization_name": "The organization",
                "homepage_uri": "https://example.com",
                "contacts": "operations@example.com"
            },
            key_config={"key_defs": DEFAULT_KEY_DEFS},
            authority_hints=[TA_ID],
            trust_anchors=ANCHOR
        )

        self.ta.server.subordinate[IM_ID] = {
            "jwks": self.im.keyjar.export_jwks(),
            'entity_types': ['federation_entity']

        }

        ########################################
        # Leaf RP
        ########################################

        oauth2_service = DEFAULT_OAUTH2_SERVICES.copy()
        oauth2_service.update(DEFAULT_OAUTH2_FED_SERVICES)
        oauth2_service['authorization'] = {"class": "fedservice.appclient.oauth2.authorization.Authorization"}

        self.rp = make_federation_combo(
            entity_id=RP_ID,
            preference={
                "organization_name": "The RP",
                "homepage_uri": "https://rp.example.com",
                "contacts": "operations@rp.example.com"
            },
            authority_hints=[IM_ID],
            key_config={"key_defs": DEFAULT_KEY_DEFS},
            endpoints=LEAF_ENDPOINTS,
            trust_anchors=ANCHOR,
            entity_type={
                "oauth_client": {
                    'class': ClientEntity,
                    'kwargs': {
                        # OIDC core keys
                        "key_conf": {"uri_path": "static/jwks.json", "key_defs": DEFAULT_KEY_DEFS},
                        'config': {
                            'client_id': RP_ID,
                            'client_secret': 'a longesh password',
                            'redirect_uris': ['https://example.com/cli/authz_cb'],
                            "preference": {
                                "grant_types": ['authorization_code', 'implicit', 'refresh_token'],
                                "id_token_signed_response_alg": "ES256",
                                "token_endpoint_auth_method": "client_secret_basic",
                                "token_endpoint_auth_signing_alg": "ES256",
                                "client_registration_types": ["explicit"],
                            },
                        },
                        "services": oauth2_service,
                        'client_type': 'oauth2'
                    }
                }
            }
        )

        self.im.server.subordinate[RP_ID] = {
            "jwks": self.rp['federation_entity'].keyjar.export_jwks(),
            'entity_types': ['federation_entity', 'oauth_client']
        }

        ########################################
        # Leaf OP
        ########################################

        _as_endpoints = DEFAULT_OAUTH2_ENDPOINTS.copy()
        _as_endpoints["register"] = {
            "path": "registration",
            "class": "fedservice.appserver.oauth2.registration.Registration",
            "kwargs": {}
        }

        self.oauth_serv = make_federation_combo(
            entity_id=OP_ID,
            preference={
                "organization_name": "The OP operator",
                "homepage_uri": "https://op.example.com",
                "contacts": "operations@op.example.com"
            },
            authority_hints=[TA_ID],
            key_config={"key_defs": DEFAULT_KEY_DEFS},
            trust_anchors=ANCHOR,
            endpoints=LEAF_ENDPOINTS,
            entity_type={
                "oauth_authorization_server": {
                    'class': ServerEntity,
                    'kwargs': {
                        'config': {
                            "issuer": "https://example.com/",
                            "httpc_params": {"verify": False, "timeout": 1},
                            "preferences": {
                                "subject_types_supported": ["public", "pairwise", "ephemeral"],
                                "grant_types_supported": [
                                    "authorization_code",
                                    "implicit",
                                    "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                    "refresh_token",
                                ],
                            },
                            "key_conf": {
                                "key_defs": DEFAULT_KEY_DEFS,
                                "uri_path": "static/jwks.json"},
                            "template_dir": "template",
                            "session_params": SESSION_PARAMS,
                            "endpoint": _as_endpoints
                        },
                        "server_type": "oauth2"
                    }
                }
            }
        )

        self.ta.server.subordinate[OP_ID] = {
            "jwks": self.oauth_serv['federation_entity'].keyjar.export_jwks(),
            'entity_types': ['federation_entity', 'oauth_authorization_server']
        }

    def test_registration_verification(self):
        # No clients registered with the OP at the beginning
        assert len(self.oauth_serv['oauth_authorization_server'].get_context().cdb.keys()) == 0

        ####################################################
        # [1] Let the RP do some provider info discovery
        # Point the RP to the OP
        self.rp['oauth_client'].get_context().issuer = self.oauth_serv.entity_id

        # Create the URLs and messages that will be involved in this process
        _msgs = create_trust_chain_messages(self.oauth_serv, self.ta)

        # add the jwks_uri
        _jwks_uri = self.oauth_serv['oauth_authorization_server'].get_context().get_preference('jwks_uri')
        _msgs[_jwks_uri] = self.oauth_serv['oauth_authorization_server'].keyjar.export_jwks_as_json()

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         headers={"Content-Type": "application/json"}, status=200)

            self.rp['oauth_client'].do_request('provider_info')

        # the provider info should have been updated

        assert self.rp['oauth_client'].get_context().provider_info

        ####################################################
        # [2] Let the RP construct the registration request

        _reg_service = self.rp['oauth_client'].get_service('registration')
        reg_request = _reg_service.construct()

        ###############################################################
        # [3] The OP receives a registration request and responds to it
        _msgs = create_trust_chain_messages(self.rp.entity_id, self.im, self.ta)
        # add the jwks_uri
        # _jwks_uri = self.oauth_serv['oauth_authorization_server'].get_preference('jwks_uri')
        # _msgs[_jwks_uri] = self.oauth_serv['oauth_authorization_server'].keyjar.export_jwks_as_json()

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         headers={"Content-Type": "application/json"}, status=200)

            # The OP handles the registration request
            resp = self.oauth_serv['oauth_authorization_server'].get_endpoint('registration').process_request(
                reg_request)

        assert resp["response_code"] == 201

        _jws = factory(resp['response_msg'])
        _payload = _jws.jwt.payload()
        assert _payload['iss'] == self.oauth_serv.entity_id
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
