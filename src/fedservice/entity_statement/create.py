import logging
from typing import Callable
from typing import Optional

from cryptojwt.jwt import JWT
from fedservice.message import ResolveResponse

from fedservice.message import EntityConfiguration
from fedservice.message import ExplicitRegistrationRequest
from fedservice.message import ExplicitRegistrationResponse
from fedservice.message import SubordinateStatement

logger = logging.getLogger(__name__)


def create_entity_statement(cls,
                            iss,
                            key_jar,
                            sub: Optional[str] = None,
                            lifetime: Optional[int] = 86400,
                            include_jwks: Optional[bool] = True,
                            signing_alg: Optional[str] = "RS256",
                            jws_header_param: Optional[dict] = None,
                            **kwargs):
    """

    :param cls: Type of Entity Statement
    :param iss: The issuer of the signed JSON Web Token
    :param sub: The subject which the metadata describes
    :param key_jar: A KeyJar instance
    :param lifetime: The lifetime of the signed JWT.
    :param include_jwks: Add JWKS
    :param signing_alg: Which signing algorithm that should be used
    :param jws_header_param: Extra JWS header parameters
    :param kwargs: Additional arguments for the JSON object
    :return: A signed JSON Web Token
    """

    msg = {}
    if cls in [SubordinateStatement, ExplicitRegistrationResponse, ExplicitRegistrationRequest,
               EntityConfiguration, ResolveResponse]:  # sub and iss not
        msg = {'sub': sub}

    if kwargs:
        for claim in cls.c_param.keys():
            if claim in kwargs:
                msg[claim] = kwargs[claim]

    if include_jwks:
        if "jwks" in kwargs:
            msg['jwks'] = kwargs['jwks']
        else:
            # The public signing keys of the subject
            msg['jwks'] = key_jar.export_jwks()

    # default
    _header_param = {'typ': "entity-statement+jwt"}
    if jws_header_param:
        _header_param.update(jws_header_param)

    packer = JWT(key_jar=key_jar, iss=iss, lifetime=lifetime, sign_alg=signing_alg)
    return packer.pack(payload=msg, jws_headers=_header_param)


def create_entity_configuration(iss, key_jar, metadata=None,
                                authority_hints=None, lifetime=86400, include_jwks=True,
                                signing_alg: Optional[str] = "RS256",
                                jws_header_param: Optional[dict] = None, **kwargs):
    """

    :param iss: The issuer of the signed JSON Web Token
    :param sub: The subject which the metadata describes
    :param key_jar: A KeyJar instance
    :param metadata: The entity's metadata organised as a dictionary with the
        entity type as key
    :param lifetime: The lifetime of the signed JWT.
    :param include_jwks: Add JWKS
    :param signing_alg: Which signing algorithm that should be used
    :return: A signed JSON Web Token
    """

    msg = {}

    if metadata:
        msg["metadata"] = metadata

    if authority_hints:
        if isinstance(authority_hints, Callable):
            msg['authority_hints'] = authority_hints()
        else:
            msg['authority_hints'] = authority_hints

    if kwargs:
        msg.update(kwargs)

    return create_entity_statement(EntityConfiguration, iss, key_jar, sub=iss, lifetime=lifetime,
                                   include_jwks=include_jwks, signing_alg=signing_alg,
                                   jws_header_param=jws_header_param, **msg)


def create_subordinate_statement(iss, key_jar, sub=None, lifetime=86400, include_jwks=True, constraints=None,
                                 signing_alg: Optional[str] = "RS256",
                                 jws_header_param: Optional[dict] = None, **kwargs):
    """

    :param iss: The issuer of the signed JSON Web Token
    :param sub: The subject which the metadata describes
    :param key_jar: A KeyJar instance
    :param lifetime: The lifetime of the signed JWT.
    :param include_jwks: Add JWKS
    :param signing_alg: Which signing algorithm that should be used
    :return: A signed JSON Web Token
    """

    if constraints:
        msg = {'constraints': constraints}
    else:
        msg = {}

    if kwargs:
        msg.update(kwargs)

    return create_entity_statement(SubordinateStatement, iss, key_jar, sub=sub, lifetime=lifetime,
                                   include_jwks=include_jwks, signing_alg=signing_alg,
                                   jws_header_param=jws_header_param, **msg)


def create_explicit_registration_request(iss, key_jar, sub, lifetime=86400, include_jwks=True,
                                         signing_alg: Optional[str] = "RS256",
                                         jws_header_param: Optional[dict] = None, **kwargs):
    msg = {}

    if kwargs:
        msg.update(kwargs)

    return create_entity_statement(ExplicitRegistrationRequest, iss, key_jar, sub=sub, lifetime=lifetime,
                                   include_jwks=include_jwks, signing_alg=signing_alg,
                                   jws_header_param=jws_header_param, **msg)


def create_explicit_registration_response(iss, key_jar, sub=None, lifetime=86400, include_jwks=True,
                                          signing_alg: Optional[str] = "RS256",
                                          jws_header_param: Optional[dict] = None, **kwargs):
    msg = {}
    if kwargs:
        msg.update(kwargs)

    return create_entity_statement(ExplicitRegistrationResponse, iss, key_jar, sub=sub, lifetime=lifetime,
                                   include_jwks=include_jwks, signing_alg=signing_alg,
                                   jws_header_param=jws_header_param, **msg)
