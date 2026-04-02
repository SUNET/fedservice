from typing import Callable

import pytest
from cryptojwt.utils import importer
from idpyoidc.transform import supported_to_preferred

from fedservice.appclient.claims.oauth2 import Claims
from fedservice.message import AuthorizationServerMetadata
from fedservice.message import OauthClientMetadata


# from fedservice.message import AuthorizationServerMetadata


class TestFedOauth2Client:

    @pytest.fixture(autouse=True)
    def setup(self):
        supported = Claims._supports.copy()
        for service in [
            "fedservice.appclient.oauth2.authorization.Authorization",
            "fedservice.appclient.oauth2.registration.Registration",
        ]:
            cls = importer(service)
            supported.update(cls._supports)

        for key, val in supported.items():
            if isinstance(val, Callable):
                supported[key] = val()
        # NOTE! Not checking rules
        self.supported = supported

    def test_supported(self):
        # These are all the available configuration parameters
        assert set(self.supported.keys()) == {'client_name',
                                              'client_uri',
                                              'client_id',
                                              'client_secret',
                                              'client_registration_types',
                                              'contacts',
                                              'grant_types',
                                              'grant_types_supported',
                                              'jwks',
                                              'jwks_uri',
                                              'logo_uri',
                                              'organization_name',
                                              'policy_uri',
                                              'redirect_uris',
                                              'response_types_supported',
                                              'scope',
                                              'signed_jwks_uri',
                                              'software_id',
                                              'software_version',
                                              'token_endpoint_auth_methods_supported',
                                              'tos_uri'}

    def test_setup(self):
        # This is AS specified stuff
        assert set(AuthorizationServerMetadata.c_param.keys()).difference(
            set(self.supported)
        ) == {'authorization_endpoint',
              'client_registration_types_supported',
              'code_challenge_methods_supported',
              'federation_registration_endpoint',
              'introspection_auth_methods_supported',
              'introspection_auth_signing_algs_supported',
              'introspection_endpoint',
              'issuer',
              'op_policy_uri',
              'op_tos_uri',
              'registration_endpoint',
              'request_authentication_methods_supported',
              'request_authentication_signing_alg_values_supported',
              'response_modes_supported',
              'revocation_auth_methods_supported',
              'revocation_auth_signing_algs_supported',
              'revocation_endpoint',
              'scopes_supported',
              'service_documentation',
              'token_auth_methods_supported',
              'token_auth_signing_algs_supported',
              'token_endpoint',
              'ui_locales_supported'}

        # parameters that are not mapped against what the AS's metadata says
        assert set(self.supported).difference(
            set(AuthorizationServerMetadata.c_param.keys())
        ) == {'client_name',
              'client_uri',
              'client_id',
              'client_secret',
              'client_registration_types',
              'contacts',
              'grant_types',
              'jwks',
              'logo_uri',
              'organization_name',
              'policy_uri',
              'redirect_uris',
              'scope',
              'signed_jwks_uri',
              'software_id',
              'software_version',
              'token_endpoint_auth_methods_supported',
              'tos_uri'}

        claims = Claims()
        # Translate supported into preferred. No input from the AS so info is absent
        claims.prefer = supported_to_preferred(
            supported=self.supported, preference=claims.prefer, base_url="https://example.com"
        )

        # These are the claims that has default values. A default value should not be an empty list.
        assert set(claims.prefer.keys()) == {'client_registration_types',
                                             'grant_types_supported',
                                             'response_types_supported',
                                             'token_endpoint_auth_methods_supported'}

        # To verify that I have all the necessary claims to do client registration
        reg_claim = []
        for key, spec in Claims.registration_request.c_param.items():
            _pref_key = Claims.register2preferred.get(key, key)
            if _pref_key in self.supported:
                reg_claim.append(key)

        # These I have not assigned any values. Which is OK since all fields are optional !
        assert set(OauthClientMetadata.c_param.keys()).difference(set(reg_claim)) == {
            'scope', 'software_statement', 'grant_type'}

        # Which ones are list -> singletons
        l_to_s = []
        # These are configurable but doesn't appear in the registration request
        non_appear = []
        for key, pref_key in Claims.register2preferred.items():
            spec = OauthClientMetadata.c_param.get(key)
            if spec is None:
                non_appear.append(pref_key)
            elif isinstance(spec[0], list):
                l_to_s.append(key)

        assert set(non_appear) == {'grant_types_supported',
                                   'token_auth_signing_algs_supported',
                                   'token_endpoint_auth_signing_alg_values_supported'}
        assert set(l_to_s) == {"response_types", "scope"}

    def test_metadata(self):
        AS_BASEURL = "https://example.com"
        provider_info_response = {
            "issuer": AS_BASEURL,
            "authorization_endpoint": f"{AS_BASEURL}/authorization",
            "token_endpoint": f"{AS_BASEURL}/token",
            "jwks_uri": f"{AS_BASEURL}/static/jwks_tE2iLbOAqXhe8bqh.json",
            "registration_endpoint": f"{AS_BASEURL}/registration",
            "scopes_supported": ["openid", "fee", "faa", "foo", "fum"],
            "response_types_supported": ["code", "id_token", "code id_token"],
            "response_modes_supported": ["query", "form_post", "new_fangled"],
            "grant_types_supported": ["authorization_code", "implicit"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "version": "3.0",
            "introspection_endpoint": f"{AS_BASEURL}/introspect",
            "introspection_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic",
                                                              "private_key_jwt"],
        }

        # Matches what the package supports against what the server supports
        claims = Claims()
        claims.prefer = supported_to_preferred(
            supported=self.supported,
            preference=claims.prefer,
            base_url="https://example.com",
            info=provider_info_response,
        )

        # These are the claims that the client has default values for after comparing with what the AS supports
        assert set(claims.prefer.keys()) == {'client_registration_types',
                                             'grant_types_supported',
                                             'response_types_supported',
                                             'token_endpoint_auth_methods_supported'}

    def test_preference(self):
        preference = {
            "redirect_uris": ["https://client.example.org/callback",
                              "https://client.example.org/callback2"],
            "client_name": "My Example Client",
            "token_endpoint_auth_method": "client_secret_basic",
            "policy_uri": "https://client.example.org/policy.html",
            "example_extension_parameter": "example_value"
        }

        claims = Claims()
        claims.prefer = supported_to_preferred(
            supported=self.supported,
            preference=preference,
            base_url="https://example.com",
        )

        reg_req = claims.create_registration_request()

        assert set(reg_req.keys()) == {'client_name',
                                       'client_registration_types',
                                       'grant_types',
                                       'example_extension_parameter',
                                       'policy_uri',
                                       'redirect_uris',
                                       'response_types',
                                       'token_endpoint_auth_method'}
