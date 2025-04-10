""" Classes and functions used to describe information in an OpenID Connect Federation."""
import logging

from cryptojwt.exception import Expired
from cryptojwt.jws.jws import factory
from cryptojwt.jwt import utc_time_sans_frac
from idpyoidc import message
from idpyoidc.exception import MissingRequiredAttribute
from idpyoidc.message import Message
from idpyoidc.message import msg_ser
from idpyoidc.message import oauth2 as OAuth2Message
from idpyoidc.message import OPTIONAL_LIST_OF_STRINGS
from idpyoidc.message import OPTIONAL_MESSAGE
from idpyoidc.message import REQUIRED_LIST_OF_STRINGS
from idpyoidc.message import SINGLE_OPTIONAL_ANY
from idpyoidc.message import SINGLE_OPTIONAL_INT
from idpyoidc.message import SINGLE_OPTIONAL_JSON
from idpyoidc.message import SINGLE_OPTIONAL_STRING
from idpyoidc.message import SINGLE_REQUIRED_INT
from idpyoidc.message import SINGLE_REQUIRED_STRING
from idpyoidc.message.oauth2 import ASConfigurationResponse
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.message.oidc import deserialize_from_one_of
from idpyoidc.message.oidc import dict_deser
from idpyoidc.message.oidc import JsonWebToken
from idpyoidc.message.oidc import msg_ser_json
from idpyoidc.message.oidc import ProviderConfigurationResponse
from idpyoidc.message.oidc import RegistrationRequest
from idpyoidc.message.oidc import RegistrationResponse
from idpyoidc.message.oidc import SINGLE_OPTIONAL_BOOLEAN
from idpyoidc.message.oidc import SINGLE_OPTIONAL_DICT

from fedservice.exception import UnknownCriticalExtension
from fedservice.exception import WrongSubject

SINGLE_REQUIRED_DICT = (dict, True, msg_ser_json, dict_deser, False)

LOGGER = logging.getLogger(__name__)


class AuthorizationServerMetadata(Message):
    """Metadata for an OAuth2 Authorization Server. With Federation additions"""
    c_param = {
        "issuer": SINGLE_REQUIRED_STRING,
        "authorization_endpoint": SINGLE_OPTIONAL_STRING,
        "token_endpoint": SINGLE_OPTIONAL_STRING,
        "jwks_uri": SINGLE_OPTIONAL_STRING,
        "registration_endpoint": SINGLE_OPTIONAL_STRING,
        "scopes_supported": OPTIONAL_LIST_OF_STRINGS,
        "response_types_supported": OPTIONAL_LIST_OF_STRINGS,
        "response_modes_supported": OPTIONAL_LIST_OF_STRINGS,
        "grant_types_supported": OPTIONAL_LIST_OF_STRINGS,
        "token_auth_methods_supported": OPTIONAL_LIST_OF_STRINGS,
        "token_auth_signing_algs_supported": OPTIONAL_LIST_OF_STRINGS,
        "service_documentation": SINGLE_OPTIONAL_STRING,
        "ui_locales_supported": OPTIONAL_LIST_OF_STRINGS,
        "op_policy_uri": SINGLE_OPTIONAL_STRING,
        "op_tos_uri": SINGLE_OPTIONAL_STRING,
        "revocation_endpoint": SINGLE_OPTIONAL_STRING,
        "revocation_auth_methods_supported": SINGLE_OPTIONAL_JSON,
        "revocation_auth_signing_algs_supported": SINGLE_OPTIONAL_JSON,
        "introspection_endpoint": SINGLE_OPTIONAL_STRING,
        "introspection_auth_methods_supported": OPTIONAL_LIST_OF_STRINGS,
        "introspection_auth_signing_algs_supported": OPTIONAL_LIST_OF_STRINGS,
        "code_challenge_methods_supported": OPTIONAL_LIST_OF_STRINGS,
        # below Federation additions
        'client_registration_types_supported': OPTIONAL_LIST_OF_STRINGS,
        'federation_registration_endpoint': SINGLE_OPTIONAL_STRING,
        'request_authentication_methods_supported': OPTIONAL_LIST_OF_STRINGS,
        'request_authentication_signing_alg_values_supported': OPTIONAL_LIST_OF_STRINGS,
    }


def auth_server_info_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into an AuthorizationServerMetadata."""
    return deserialize_from_one_of(val, AuthorizationServerMetadata, sformat)


OPTIONAL_AUTH_SERVER_METADATA = (Message, False, msg_ser, auth_server_info_deser, False)


class NamingConstraints(Message):
    """Class representing naming constraints."""
    c_param = {
        "permitted": OPTIONAL_LIST_OF_STRINGS,
        "excluded": OPTIONAL_LIST_OF_STRINGS
    }


def naming_constraints_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into an NamingConstraints."""
    return deserialize_from_one_of(val, NamingConstraints, sformat)


SINGLE_OPTIONAL_NAMING_CONSTRAINTS = (Message, False, msg_ser, naming_constraints_deser, False)

class InformationalMetadataExtensions(Message):
    c_param = {
        "organization_name": SINGLE_OPTIONAL_STRING,
        "contacts": OPTIONAL_LIST_OF_STRINGS,
        "logo_url": SINGLE_OPTIONAL_STRING,
        "policy_url": SINGLE_OPTIONAL_STRING,
        "homepage_uri": SINGLE_OPTIONAL_STRING,
    }

class FederationEntity(InformationalMetadataExtensions):
    """Class representing Federation Entity metadata."""
    c_param = InformationalMetadataExtensions.c_param.copy()
    c_param.update({
        "federation_fetch_endpoint": SINGLE_OPTIONAL_STRING,
        "federation_list_endpoint": SINGLE_OPTIONAL_STRING,
        "federation_resolve_endpoint": SINGLE_OPTIONAL_STRING,
        "federation_trust_mark_status_endpoint": SINGLE_OPTIONAL_STRING,
        "federation_trust_mark_list_endpoint": SINGLE_OPTIONAL_STRING,
        "federation_trust_mark_endpoint": SINGLE_OPTIONAL_STRING,
        "federation_historical_keys_endpoint": SINGLE_OPTIONAL_STRING,
        "endpoint_auth_signing_alg_values_supported": SINGLE_OPTIONAL_JSON,
        # If it's a Trust Anchor
        # "trust_mark_owners": SINGLE_OPTIONAL_DICT,
        # "trust_mark_issuers": SINGLE_OPTIONAL_DICT,
    })


def federation_entity_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a FederationEntity."""
    return deserialize_from_one_of(val, FederationEntity, sformat)


OPTIONAL_FEDERATION_ENTITY_METADATA = (Message, False, msg_ser,
                                       federation_entity_deser, False)


class TrustMarkIssuer(Message):
    c_param = {
        "federation_status_endpoint": SINGLE_OPTIONAL_STRING
    }


def trust_mark_issuer_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a FederationEntity."""
    return deserialize_from_one_of(val, TrustMarkIssuer, sformat)


class OauthClientMetadata(OAuth2Message.OauthClientMetadata):
    """Metadata for an OAuth2 Client."""
    c_param = OAuth2Message.OauthClientMetadata.c_param.copy()
    c_param.update({
        "organization_name": SINGLE_OPTIONAL_STRING,
        "signed_jwks_uri": SINGLE_OPTIONAL_STRING,
    })


def oauth_client_metadata_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a OauthClientMetadata."""
    return deserialize_from_one_of(val, OauthClientMetadata, sformat)


OPTIONAL_OAUTH_CLIENT_METADATA = (Message, False, msg_ser,
                                  oauth_client_metadata_deser, False)


class OauthClientInformationResponse(OauthClientMetadata):
    """The information returned by a OAuth2 Server about an OAuth2 client."""
    c_param = OauthClientMetadata.c_param.copy()
    c_param.update({
        "client_id": SINGLE_REQUIRED_STRING,
        "client_secret": SINGLE_OPTIONAL_STRING,
        "client_id_issued_at": SINGLE_OPTIONAL_INT,
        "client_secret_expires_at": SINGLE_OPTIONAL_INT
    })

    def verify(self, **kwargs):
        super(OauthClientInformationResponse, self).verify(**kwargs)

        if "client_secret" in self:
            if "client_secret_expires_at" not in self:
                raise MissingRequiredAttribute(
                    "client_secret_expires_at is a MUST if client_secret is present")


def oauth_client_registration_response_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a OauthClientInformationResponse."""
    return deserialize_from_one_of(val, OauthClientInformationResponse, sformat)


OPTIONAL_OAUTH_CLIENT_REGISTRATION_RESPONSE = (
    Message, False, msg_ser, oauth_client_registration_response_deser, False)


class OAuthProtectedResourceMetadata(Message):
    c_param = {
        "resource": SINGLE_REQUIRED_STRING,
        "authorization_servers": OPTIONAL_LIST_OF_STRINGS,
        "jwks_uri": SINGLE_OPTIONAL_STRING,
        "scopes_provided": OPTIONAL_LIST_OF_STRINGS,
        "bearer_methods_supported": OPTIONAL_LIST_OF_STRINGS,
        "resource_signing_alg_values_supported": OPTIONAL_LIST_OF_STRINGS,
        "client_registration_types": OPTIONAL_LIST_OF_STRINGS,
        "organization_name": SINGLE_OPTIONAL_STRING,
    }


def oauth_protected_resource_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a OAuthProtectedResourceMetadata."""
    return deserialize_from_one_of(val, OAuthProtectedResourceMetadata, sformat)


OPTIONAL_OAUTH_PROTECTED_RESOURCE_METADATA = (
    Message, False, msg_ser, oauth_protected_resource_deser, False)


class OIDCRPMetadata(RegistrationRequest):
    c_param = RegistrationRequest.c_param.copy()
    c_param.update({
        "client_registration_types": REQUIRED_LIST_OF_STRINGS
    })


def rp_metadata_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a OIDCRPMetadata."""
    return deserialize_from_one_of(val, OIDCRPMetadata, sformat)


OPTIONAL_RP_METADATA = (
    Message, False, msg_ser, rp_metadata_deser, False)


class OIDCRPRegistrationResponse(RegistrationResponse):
    c_param = RegistrationResponse.c_param.copy()
    c_param.update({
        "client_registration_types": REQUIRED_LIST_OF_STRINGS
    })


def rp_registration_response_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a OIDCRPRegistrationResponse."""
    return deserialize_from_one_of(val, OIDCRPRegistrationResponse, sformat)


OPTIONAL_RP_REGISTRATION_RESPONSE = (
    Message, False, msg_ser, rp_registration_response_deser, False)


class OPMetadata(ProviderConfigurationResponse):
    c_param = ProviderConfigurationResponse.c_param.copy()
    c_param.update({
        "client_registration_types_supported": REQUIRED_LIST_OF_STRINGS,
        "federation_registration_endpoint": SINGLE_OPTIONAL_STRING,
        "request_authentication_methods_supported": SINGLE_OPTIONAL_JSON,
        "request_authentication_signing_alg_values_supported": OPTIONAL_LIST_OF_STRINGS,
        "organization_name": SINGLE_OPTIONAL_STRING,
        "contacts": OPTIONAL_LIST_OF_STRINGS,
        "logo_uri": SINGLE_OPTIONAL_STRING,
        "policy_uri": SINGLE_OPTIONAL_STRING,
        "homepage_uri": SINGLE_OPTIONAL_STRING,
        "jwks": SINGLE_OPTIONAL_DICT,
        "jwks_uri": SINGLE_OPTIONAL_STRING,
        "signed_jwks_uri": SINGLE_OPTIONAL_STRING
    })


class FedASConfigurationResponse(ASConfigurationResponse):
    c_param = ASConfigurationResponse.c_param.copy()
    c_param.update({
        "organization_name": SINGLE_OPTIONAL_STRING,
        "contacts": OPTIONAL_LIST_OF_STRINGS,
        "logo_uri": SINGLE_OPTIONAL_STRING,
        "policy_uri": SINGLE_OPTIONAL_STRING,
        "homepage_uri": SINGLE_OPTIONAL_STRING,
        "jwks": SINGLE_OPTIONAL_DICT,
        "jwks_uri": SINGLE_OPTIONAL_STRING,
        "signed_jwks_uri": SINGLE_OPTIONAL_STRING
    })


def op_metadata_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a ProviderConfigurationResponse."""
    return deserialize_from_one_of(val, OPMetadata, sformat)


OPTIONAL_OP_METADATA = (Message, False, msg_ser, op_metadata_deser, False)


class TrustMarkIssuerMetadata(Message):
    """Metadata for a Trust Mark Issuer."""
    c_param = {
        "status_endpoint": SINGLE_REQUIRED_STRING
    }


def trust_mark_issuer_metadata_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a OauthClientMetadata."""
    return deserialize_from_one_of(val, TrustMarkIssuerMetadata, sformat)


OPTIONAL_TRUST_MARK_ISSUER_METADATA = (Message, False, msg_ser,
                                       trust_mark_issuer_metadata_deser, False)


class Metadata(Message):
    """The different types of metadata that an entity in a federation can belong to."""
    c_param = {
        'openid_relying_party': OPTIONAL_RP_METADATA,
        'openid_provider': OPTIONAL_OP_METADATA,
        "oauth_authorization_server": OPTIONAL_AUTH_SERVER_METADATA,
        "oauth_client": OPTIONAL_OAUTH_CLIENT_METADATA,
        "oauth_response_server": OPTIONAL_OAUTH_PROTECTED_RESOURCE_METADATA,
        "federation_entity": OPTIONAL_FEDERATION_ENTITY_METADATA,
        "trust_mark_issuer": OPTIONAL_TRUST_MARK_ISSUER_METADATA
    }


def metadata_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a MetadataPolicy."""
    return deserialize_from_one_of(val, Metadata, sformat)


SINGLE_REQUIRED_METADATA = (Message, True, msg_ser, metadata_deser, False)
SINGLE_OPTIONAL_METADATA = (Message, False, msg_ser, metadata_deser, False)


class Policy(Message):
    """The metadata policy verbs."""
    c_param = {
        "subset_of": OPTIONAL_LIST_OF_STRINGS,
        "one_of": OPTIONAL_LIST_OF_STRINGS,
        "superset_of": OPTIONAL_LIST_OF_STRINGS,
        "add": OPTIONAL_LIST_OF_STRINGS,
        "value": SINGLE_OPTIONAL_ANY,
        "default": SINGLE_OPTIONAL_ANY,
        "essential": SINGLE_OPTIONAL_BOOLEAN
    }

    def verify(self, **kwargs):
        _extra_parameters = list(self.extra().keys())
        if _extra_parameters:
            _critical = kwargs.get("policy_language_crit")
            if _critical is None:
                pass
            elif not _critical:
                raise ValueError("Empty list not allowed for 'policy_language_crit'")
            else:
                _musts = set(_critical).intersection(_extra_parameters)
                _known = kwargs.get("known_policy_extensions")
                if _known:
                    if set(_known).issuperset(set(_musts)) is False:
                        raise UnknownCriticalExtension(_musts.difference(set(_known)))
                else:
                    raise UnknownCriticalExtension(_musts.intersection(_extra_parameters))


def policy_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a MetadataPolicy."""
    return deserialize_from_one_of(val, Policy, sformat)


SINGLE_REQUIRED_POLICY = (Message, True, msg_ser, policy_deser, False)
SINGLE_OPTIONAL_POLICY = (Message, False, msg_ser, policy_deser, False)


class MetadataPolicy(Message):
    """The different types of metadata that an entity in a federation can belong to."""
    c_param = {
        'openid_relying_party': OPTIONAL_MESSAGE,
        'openid_provider': OPTIONAL_MESSAGE,
        "oauth_authorization_server": OPTIONAL_MESSAGE,
        "oauth_client": OPTIONAL_MESSAGE,
        "federation_entity": OPTIONAL_MESSAGE,
        "trust_mark_issuer": OPTIONAL_MESSAGE
    }

    def verify(self, **kwargs):
        for typ, _policy in self.items():
            for attr, item in _policy.items():
                _p = Policy(**item)
                _p.verify(**kwargs)


def metadata_policy_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a MetadataPolicy."""
    return deserialize_from_one_of(val, MetadataPolicy, sformat)


SINGLE_REQUIRED_METADATA_POLICY = (Message, True, msg_ser, metadata_policy_deser, False)
SINGLE_OPTIONAL_METADATA_POLICY = (Message, False, msg_ser, metadata_policy_deser, False)


class Constraints(Message):
    """The types of constraints that can be applied to a trust chain."""
    c_param = {
        "max_path_length": SINGLE_OPTIONAL_INT,
        "naming_constraints": SINGLE_OPTIONAL_NAMING_CONSTRAINTS
    }


def constrains_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a Constraints."""
    return deserialize_from_one_of(val, Constraints, sformat)


SINGLE_REQUIRED_CONSTRAINS = (Message, True, msg_ser, constrains_deser, False)
SINGLE_OPTIONAL_CONSTRAINS = (Message, False, msg_ser, constrains_deser, False)


class TrustMarks(Message):
    c_param = {}

    def verify(self, **kwargs):
        for _id, spec in self.items():
            _trust_mark = spec.get("trust_mark")
            if _trust_mark:
                _trust_mark_id = spec.get("trust_mark_id")
                if _trust_mark_id:
                    # Have to peek into the trust mark
                    _jws = factory(_trust_mark)
                    if not _jws:
                        raise ValueError(f"Not a proper signed JWT: {_trust_mark}")
                    _tm_id = _jws.jwt.payload().get("trust_mark_id")
                    if _tm_id != _trust_mark_id:
                        raise ValueError("The Trust Mark identifier MUST have the same value as the trust_mark_id "
                                         "claim")
                else:
                    raise MissingRequiredAttribute("trust_mark_id")
            else:
                raise MissingRequiredAttribute("trust_mark")


class TrustMarkIssuers(Message):
    c_param = {}

    def verify(self, **kwargs):
        for owner_id, spec in self.items():
            if not isinstance(spec, list):
                raise ValueError("issuers MUST be a list")


class TrustMarkOwners(Message):

    def verify(self, **kwargs):
        # Dictionary of Trust Mark Owner information
        for owner_id, spec in self.items():
            if "sub" in spec and "jwks" in spec:  # If there are other claims ignore them
                continue
            else:
                if "sub" not in spec:
                    raise MissingRequiredAttribute("sub")
                elif "jwks" not in spec:
                    raise MissingRequiredAttribute("jwks")


class EntityStatement(JsonWebToken):
    """The Entity Statement"""
    c_param = JsonWebToken.c_param.copy()
    c_param.update({
        "sub": SINGLE_REQUIRED_STRING,
        'iss': SINGLE_REQUIRED_STRING,
        'exp': SINGLE_REQUIRED_INT,
        'iat': SINGLE_REQUIRED_INT,
        'jwks': SINGLE_OPTIONAL_DICT,
        'aud': SINGLE_OPTIONAL_STRING,
        "jti": SINGLE_OPTIONAL_STRING,
        'authority_hints': OPTIONAL_LIST_OF_STRINGS,
        'metadata': SINGLE_OPTIONAL_METADATA,
        'metadata_policy': SINGLE_OPTIONAL_METADATA_POLICY,
        'metadata_policy_crit': OPTIONAL_LIST_OF_STRINGS,
        'constraints': SINGLE_OPTIONAL_CONSTRAINS,
        "crit": OPTIONAL_LIST_OF_STRINGS,
        "policy_language_crit": OPTIONAL_LIST_OF_STRINGS,
        "source_endpoint": SINGLE_OPTIONAL_STRING,
        'trust_marks': SINGLE_OPTIONAL_JSON,
        'trust_mark_owners': SINGLE_OPTIONAL_JSON,
        'trust_mark_issuers': SINGLE_OPTIONAL_JSON,
        #
        'trust_anchor_id': SINGLE_OPTIONAL_STRING
    })

    def verify(self, **kwargs):
        super(EntityStatement, self).verify(**kwargs)

        _extra_parameters = list(self.extra().keys())
        if _extra_parameters:
            _critical = self.get("crit")
            if _critical is None:
                pass
            elif not _critical:
                raise ValueError("Empty list not allowed for 'crit'")
            else:
                _musts = set(_critical).intersection(_extra_parameters)
                _known = kwargs.get("known_extensions")
                if _known:
                    if set(_known).issuperset(set(_musts)) is False:
                        raise UnknownCriticalExtension(_musts.difference(set(_known)))
                else:
                    raise UnknownCriticalExtension(_musts.intersection(_extra_parameters))

        _metadata_policy = self.get('metadata_policy')
        if _metadata_policy:
            _crit = self.get("policy_language_crit")
            if _crit:
                _metadata_policy.verify(policy_language_crit=_crit, **kwargs)

        _trust_mark_issuers = self.get("trust_mark_issuers")
        if _trust_mark_issuers:
            _tmi = TrustMarkIssuers(**_trust_mark_issuers)
            _tmi.verify()

        _trust_mark_owners = self.get("trust_mark_owners")
        if _trust_mark_owners:
            _tmi = TrustMarkOwners(**_trust_mark_owners)
            _tmi.verify()


class TrustMark(JsonWebToken):
    c_param = JsonWebToken.c_param.copy()
    c_param.update({
        "sub": SINGLE_REQUIRED_STRING,
        'iss': SINGLE_REQUIRED_STRING,
        'iat': SINGLE_REQUIRED_INT,
        "trust_mark_id": SINGLE_REQUIRED_STRING,
        "logo_uri": SINGLE_OPTIONAL_STRING,
        "exp": SINGLE_OPTIONAL_INT,
        "ref": SINGLE_OPTIONAL_STRING,
        "delegation": SINGLE_OPTIONAL_STRING
    })

    def verify(self, **kwargs):
        super(TrustMark, self).verify(**kwargs)

        entity_id = kwargs.get("entity_id")

        if entity_id is not None and entity_id != self["sub"]:
            raise WrongSubject("Mismatch between subject in trust mark and entity_id of entity")

        exp = kwargs.get("exp", 0)
        if exp:
            _now = utc_time_sans_frac()
            if _now > exp:  # have passed the time of expiration
                raise Expired()

        return True


class TrustMarkStatusRequest(Message):
    c_param = {
        "sub": SINGLE_OPTIONAL_STRING,
        "trust_mark_id": SINGLE_OPTIONAL_STRING,
        "iat": SINGLE_OPTIONAL_INT,
        "trust_mark": SINGLE_OPTIONAL_STRING
    }

    def verify(self, **kwargs):
        if 'trust_mark' not in self:
            if 'sub' not in self or 'trust_mark_id' not in self:
                raise AttributeError('Must have both "sub" and "trust_mark_id" or "trust_mark"')


def trust_mark_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a Trust Mark."""
    return deserialize_from_one_of(val, TrustMark, sformat)


SINGLE_REQUIRED_TRUST_MARK = (Message, True, msg_ser, trust_mark_deser, False)
OPTIONAL_LIST_OF_TRUST_MARKS = ([Message], False, msg_ser, trust_mark_deser, False)


class ResolveRequest(Message):
    c_param = {
        "sub": SINGLE_REQUIRED_STRING,
        "anchor": SINGLE_REQUIRED_STRING,
        "type": SINGLE_OPTIONAL_STRING
    }


class ResolveResponse(JsonWebToken):
    c_param = JsonWebToken.c_param.copy()
    c_param.update({
        'metadata': SINGLE_REQUIRED_METADATA,
        'trust_chain': OPTIONAL_LIST_OF_STRINGS,
        'trust_marks': OPTIONAL_LIST_OF_TRUST_MARKS
    })


class ListRequest(Message):
    c_param = {
        "entity_type": SINGLE_OPTIONAL_STRING,
        "trust_marked": SINGLE_OPTIONAL_BOOLEAN,
        "trust_mark_id": SINGLE_OPTIONAL_STRING,
        "intermediate": SINGLE_OPTIONAL_BOOLEAN
    }


class ListResponse(Message):
    c_param = {
        "entity_id": REQUIRED_LIST_OF_STRINGS
    }


class ProviderConfigurationResponse(message.oidc.ProviderConfigurationResponse):
    c_param = message.oidc.ProviderConfigurationResponse.c_param.copy()
    c_param.update({
        'client_registration_types_supported': REQUIRED_LIST_OF_STRINGS,
        'federation_registration_endpoint': SINGLE_OPTIONAL_STRING,
        'request_authentication_methods_supported': SINGLE_OPTIONAL_JSON,
        'request_authentication_signing_alg_values_supported': OPTIONAL_LIST_OF_STRINGS,
        'organization_name': SINGLE_OPTIONAL_STRING,
        'signed_jwks_uri': SINGLE_OPTIONAL_STRING,
        'jwks': SINGLE_OPTIONAL_JSON
    })


class RegistrationRequest(message.oidc.RegistrationRequest):
    c_param = message.oidc.RegistrationRequest.c_param.copy()
    c_param.update({
        'client_registration_types': REQUIRED_LIST_OF_STRINGS,
        'organization_name': SINGLE_OPTIONAL_STRING,
        'signed_jwks_uri': SINGLE_OPTIONAL_STRING,
        'jwks': SINGLE_OPTIONAL_JSON,
        "claims_parameter_supported": OPTIONAL_LIST_OF_STRINGS,
        "response_types_supported": OPTIONAL_LIST_OF_STRINGS,
        "response_modes_supported": OPTIONAL_LIST_OF_STRINGS,
        "request_object_signing_alg_values_supported": OPTIONAL_LIST_OF_STRINGS,
        "request_object_encryption_alg_values_supported": OPTIONAL_LIST_OF_STRINGS,
        "request_object_encryption_enc_values_supported": OPTIONAL_LIST_OF_STRINGS,
        "code_challenge_methods_supported": OPTIONAL_LIST_OF_STRINGS,
        "scopes_supported": OPTIONAL_LIST_OF_STRINGS,
        "claims_suppported": OPTIONAL_LIST_OF_STRINGS
    })


class RegistrationResponse(ResponseMessage):
    """
    Response to client_register registration requests
    """

    c_param = ResponseMessage.c_param.copy()
    c_param.update(
        {
            "client_id": SINGLE_REQUIRED_STRING,
            "client_secret": SINGLE_OPTIONAL_STRING,
            "registration_access_token": SINGLE_OPTIONAL_STRING,
            "registration_client_uri": SINGLE_OPTIONAL_STRING,
            "client_id_issued_at": SINGLE_OPTIONAL_INT,
            "client_secret_expires_at": SINGLE_OPTIONAL_INT,
        }
    )
    c_param.update(RegistrationRequest.c_param)


class HistoricalKeysResponse(Message):
    c_param = {
        'iss': SINGLE_REQUIRED_STRING,
        'iat': SINGLE_REQUIRED_INT,
        'jwks': SINGLE_REQUIRED_DICT
    }


class TrustMarkRequest(Message):
    c_param = {
        "trust_mark_id": SINGLE_REQUIRED_STRING,
        "sub": SINGLE_REQUIRED_STRING
    }


class WhoRequest(Message):
    c_param = {
        "entity_type": SINGLE_OPTIONAL_STRING,
        "credential_type": SINGLE_OPTIONAL_STRING,
        "trust_mark_id": SINGLE_OPTIONAL_STRING
    }


class WhoResponse(Message):
    c_param = {
        "entities_to_use": REQUIRED_LIST_OF_STRINGS
    }
