from typing import Callable

import pytest
from cryptojwt.utils import importer
from idpyoidc.transform import supported_to_preferred

# from idpyoidc.client.claims.transform import supported_to_preferred
from fedservice.appclient.claims.oidc import Claims
from fedservice.message import OIDCRPMetadata
from fedservice.message import OPMetadata


class TestFedOIDCClient:

    @pytest.fixture(autouse=True)
    def setup(self):
        supported = Claims._supports.copy()
        for service in [
            "fedservice.appclient.oidc.authorization.Authorization",
            "fedservice.appclient.oidc.registration.Registration",
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
        assert set(self.supported.keys()) == {'acr_values_supported',
                                              'application_type',
                                              'callback_uris',
                                              'client_id',
                                              'client_name',
                                              'client_registration_types',
                                              'client_secret',
                                              'client_uri',
                                              'code_challenge_methods_supported',
                                              'contacts',
                                              'default_max_age',
                                              'encrypt_id_token_supported',
                                              'encrypt_request_object_supported',
                                              'id_token_encryption_alg_values_supported',
                                              'id_token_encryption_enc_values_supported',
                                              'id_token_signing_alg_values_supported',
                                              'initiate_login_uri',
                                              'jwks',
                                              'jwks_uri',
                                              'logo_uri',
                                              'organization_name',
                                              'policy_uri',
                                              'redirect_uris',
                                              'request_object_encryption_alg_values_supported',
                                              'request_object_encryption_enc_values_supported',
                                              'request_object_signing_alg_values_supported',
                                              'request_parameter',
                                              'request_parameter_supported',
                                              'request_uri_parameter_supported',
                                              'request_uris',
                                              'requests_dir',
                                              'require_auth_time',
                                              'response_modes_supported',
                                              'response_types_supported',
                                              'scopes_supported',
                                              'sector_identifier_uri',
                                              'signed_jwks_uri',
                                              'subject_types_supported',
                                              'tos_uri'}

    def test_setup(self):
        # This is OP specified stuff
        assert set(OPMetadata.c_param.keys()).difference(
            set(self.supported)
        ) == {'authorization_endpoint',
              'backchannel_logout_session_required',
              'backchannel_logout_supported',
              'check_session_iframe',
              'claim_types_supported',
              'claims_locales_supported',
              'claims_parameter_supported',
              'claims_supported',
              'client_registration_types_supported',
              #'code_challenge_methods_supported',
              'display_values_supported',
              'end_session_endpoint',
              'error',
              'error_description',
              'error_uri',
              'federation_registration_endpoint',
              'frontchannel_logout_session_required',
              'frontchannel_logout_supported',
              'grant_types_supported',
              'homepage_uri',
              'issuer',
              'op_policy_uri',
              'op_tos_uri',
              'registration_endpoint',
              'request_authentication_methods_supported',
              'request_authentication_signing_alg_values_supported',
              'require_request_uri_registration',
              'service_documentation',
              'token_endpoint',
              'token_endpoint_auth_methods_supported',
              'token_endpoint_auth_signing_alg_values_supported',
              'ui_locales_supported',
              'userinfo_encryption_alg_values_supported',
              'userinfo_encryption_enc_values_supported',
              'userinfo_endpoint',
              'userinfo_signing_alg_values_supported'}

        # parameters that are not mapped against what the AS's metadata says
        assert set(self.supported).difference(
            set(OPMetadata.c_param.keys())
        ) == {'application_type',
              'callback_uris',
              'client_id',
              'client_name',
              'client_registration_types',
              'client_secret',
              'client_uri',
              'default_max_age',
              'encrypt_id_token_supported',
              'encrypt_request_object_supported',
              'initiate_login_uri',
              'redirect_uris',
              'request_parameter',
              'request_uris',
              'requests_dir',
              'require_auth_time',
              'sector_identifier_uri',
              'tos_uri'}

        claims = Claims()
        # Translate supported into preferred. No input from the AS so info is absent
        claims.prefer = supported_to_preferred(
            supported=self.supported, preference=claims.prefer, base_url="https://example.com"
        )

        # These are the claims that has default values. A default value may be an empty list.
        assert set(claims.prefer.keys()) == {'application_type',
                                             'client_registration_types',
                                             'default_max_age',
                                             'encrypt_request_object_supported',
                                             'id_token_encryption_alg_values_supported',
                                             'id_token_encryption_enc_values_supported',
                                             'id_token_signing_alg_values_supported',
                                             'request_object_encryption_alg_values_supported',
                                             'request_object_encryption_enc_values_supported',
                                             'request_object_signing_alg_values_supported',
                                             "request_parameter_supported",
                                             'response_modes_supported',
                                             'response_types_supported',
                                             'scopes_supported',
                                             'subject_types_supported'}

        # To verify that I have all the necessary claims to do client registration
        reg_claim = []
        for key, spec in Claims.registration_request.c_param.items():
            _pref_key = Claims.register2preferred.get(key, key)
            if _pref_key in self.supported:
                reg_claim.append(key)

        # These I have not assigned any values. Which is OK since they are optional !
        assert set(OIDCRPMetadata.c_param.keys()).difference(set(reg_claim)) == {'application_type',
                                                                                 'backchannel_logout_session_required',
                                                                                 'backchannel_logout_uri',
                                                                                 'client_registration_types',
                                                                                 'default_acr_values',
                                                                                 'default_max_age',
                                                                                 'frontchannel_logout_session_required',
                                                                                 'frontchannel_logout_uri',
                                                                                 'grant_types',
                                                                                 'id_token_encrypted_response_alg',
                                                                                 'id_token_encrypted_response_enc',
                                                                                 'id_token_signed_response_alg',
                                                                                 'initiate_login_uri',
                                                                                 'post_logout_redirect_uri',
                                                                                 'request_object_encryption_alg',
                                                                                 'request_object_encryption_enc',
                                                                                 'request_object_signing_alg',
                                                                                 'request_uris',
                                                                                 'require_auth_time',
                                                                                 'response_modes',
                                                                                 'sector_identifier_uri',
                                                                                 'subject_type',
                                                                                 'token_endpoint_auth_method',
                                                                                 'token_endpoint_auth_signing_alg',
                                                                                 'userinfo_encrypted_response_alg',
                                                                                 'userinfo_encrypted_response_enc',
                                                                                 'userinfo_signed_response_alg'}

        # Which ones are list -> singletons
        l_to_s = []
        # These are configurable but doesn't appear in the registration request
        non_appear = []
        for key, pref_key in Claims.register2preferred.items():
            spec = OIDCRPMetadata.c_param.get(key)
            if spec is None:
                non_appear.append(pref_key)
            elif isinstance(spec[0], list):
                l_to_s.append(key)

        assert set(non_appear) == {'scopes_supported'}
        assert set(l_to_s) == {'default_acr_values', 'response_types', 'grant_types'}

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
        assert set(claims.prefer.keys()) == {'application_type',
                                             'client_registration_types',
                                             'default_max_age',
                                             'id_token_encryption_alg_values_supported',
                                             'id_token_encryption_enc_values_supported',
                                             'id_token_signing_alg_values_supported',
                                             'request_object_encryption_alg_values_supported',
                                             'request_object_encryption_enc_values_supported',
                                             'request_object_signing_alg_values_supported',
                                             'request_parameter_supported',
                                             'response_modes_supported',
                                             'response_types_supported',
                                             'scopes_supported',
                                             'subject_types_supported'}
