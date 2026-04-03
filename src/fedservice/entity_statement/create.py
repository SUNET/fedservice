import logging
from typing import Callable
from typing import Optional

from cryptojwt.jwt import JWT

logger = logging.getLogger(__name__)


def create_entity_statement(iss, sub, key_jar, lifetime=86400, include_jwks=True,
                            signing_alg: Optional[str] = "RS256", **kwargs):
    """

    :param iss: The issuer of the signed JSON Web Token
    :param sub: The subject which the metadata describes
    :param key_jar: A KeyJar instance
    :param lifetime: The lifetime of the signed JWT.
    :param include_jwks: Add JWKS
    :param signing_alg: Which signing algorithm that should be used
    :param kwargs: Additional arguments for the JSON object
    :return: A signed JSON Web Token
    """

    msg = {'sub': sub}

    if kwargs:
        msg.update(kwargs)

    if include_jwks:
        if "jwks" in kwargs:
            msg['jwks'] = kwargs['jwks']
        else:
            # The public signing keys of the subject
            msg['jwks'] = key_jar.export_jwks()

    packer = JWT(key_jar=key_jar, iss=iss, lifetime=lifetime, sign_alg=signing_alg)
    return packer.pack(payload=msg, jws_headers={'typ': "entity-statement+jwt"})


def create_entity_configuration(iss, key_jar, metadata=None,
                                authority_hints=None, lifetime=86400, include_jwks=True,
                                signing_alg: Optional[str] = "RS256", **kwargs):
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

    return create_entity_statement(iss, iss, key_jar, lifetime=lifetime, include_jwks=include_jwks,
                                   signing_alg=signing_alg, **msg)


def create_subordinate_statement(iss, sub, key_jar, lifetime=86400, include_jwks=True, constraints=None,
                                 signing_alg: Optional[str] = "RS256", **kwargs):
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

    return create_entity_statement(iss, sub, key_jar, lifetime=lifetime, include_jwks=include_jwks,
                                   signing_alg=signing_alg, **msg)
