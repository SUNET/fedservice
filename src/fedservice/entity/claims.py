from typing import Optional

from idpyoidc import alg_info
from idpyoidc.claims import Claims as ClaimsBase
from idpyoidc.client.claims import oauth2 as OAuth2ClientClaims
from idpyoidc.client.claims import oidc as OIDCClientClaims
from idpyoidc.message import Message
from idpyoidc.server.claims import oauth2 as OAUTH2ServerClaims
from idpyoidc.server.claims import oidc as OIDCServerClaims
from idpyoidc.transform import REGISTER2PREFERRED
from idpyoidc.transform import create_registration_request

from fedservice import message


class OPClaims(OIDCServerClaims.Claims):
    _supports = OIDCServerClaims.Claims._supports.copy()
    _supports.update({
        'client_registration_types_supported': ['automatic', 'explicit'],
        'request_authentication_methods_supported': {
            "authorization_endpoint": [
                "request_object"
            ],
            "pushed_authorization_request_endpoint": [
                "request_object",
                "private_key_jwt"
            ]
        },
        'request_authentication_signing_alg_values_supported': alg_info.get_signing_algs,
        'federation_registration_endpoint': None
    })

    def provider_info(self, supports, schema: Optional[Message] = None):
        _info = {}
        if schema is None:
            schema = message.OPMetadata

        for key in schema.c_param.keys():
            _val = self.get_preference(key, supports.get(key, None))
            if _val is not None:
                _info[key] = _val
        return _info


class ASClaims(OAUTH2ServerClaims.Claims):
    _supports = OAUTH2ServerClaims.Claims._supports.copy()
    _supports.update({
        'client_registration_types_supported': ['automatic', 'explicit'],
        'request_authentication_methods_supported': {
            "authorization_endpoint": [
                "request_object"
            ],
            "pushed_authorization_request_endpoint": [
                "request_object",
                "private_key_jwt"
            ]
        },
        'request_authentication_signing_alg_values_supported': alg_info.get_signing_algs,
        'federation_registration_endpoint': None
    })

    def verify_rules(self, **kwargs):
        pass

    def provider_info(self, supports):
        _info = {}
        for key in message.AuthorizationServerMetadata.c_param.keys():
            _val = self.get_preference(key, supports.get(key, None))
            if _val is not None:
                _info[key] = _val
        return _info


class RPClaims(OIDCClientClaims.Claims):
    _supports = OIDCClientClaims.Claims._supports.copy()

    register2preferred = OIDCClientClaims.REGISTER2PREFERRED
    registration_response = message.OIDCRPRegistrationResponse
    registration_request = message.OIDCRPMetadata


class ClientClaims(OAuth2ClientClaims.Claims):
    _supports = OAuth2ClientClaims.Claims._supports.copy()

    register2preferred = REGISTER2PREFERRED
    registration_response = message.OauthClientInformationResponse
    registration_request = message.OauthClientMetadata


class FederationEntityClaims(ClaimsBase):
    _supports = {
        'trust_mark_owners': None,
        'trust_mark_issuers': None,
        "endpoint_auth_signing_alg_values_supported": alg_info.get_signing_algs(),
    }

    def metadata(self, supports):
        _info = {}
        for key in message.FederationEntity.c_param.keys():
            _val = self.get_preference(key, supports.get(key, None))
            if _val is not None:
                _info[key] = _val
        return _info

    def get_id(self, configuration: dict):
        return ''

    def create_registration_request(self):
        return create_registration_request(self.prefer, self.supports())
