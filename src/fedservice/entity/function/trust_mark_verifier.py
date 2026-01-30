import logging
from typing import Callable
from typing import Optional

from cryptojwt import as_unicode
from cryptojwt import KeyJar
from cryptojwt.exception import Expired
from cryptojwt.jws.jws import factory
from idpyoidc.key_import import import_jwks
from idpyoidc.message import Message
from idpyoidc.util import keyjar_combination

from fedservice import message
from fedservice.entity import apply_policies
from fedservice.entity import FederationEntity
from fedservice.entity.function import Function
from fedservice.entity.function import get_verified_trust_chains
from fedservice.entity.function.trust_anchor import get_verified_trust_anchor_statement
from fedservice.entity.utils import get_federation_entity
from fedservice.message import TrustMark
from fedservice.message import TrustMarkDelegation

logger = logging.getLogger(__name__)


class TrustMarkVerifier(Function):
    """
    The steps are:
    1) Verify the trust mark itself. That is; that it contains all the required claims and has not expired.
    2) Check that the trust mark issuer is recognized by the trust anchor
    3) If delegation is active.
        a) verify that the delegator is recognized by the trust anchor
        b) verify the signature of the delegation
    4) Find a trust chain to the trust mark issuer
    5) Verify the signature of the trust mark
    """

    def __init__(self, upstream_get: Optional[Callable] = None,
                 federation_entity: Optional[FederationEntity] = None
                 ):
        if not upstream_get and not federation_entity:
            raise ValueError("Must have one of upstream_get and federation_entity")
        Function.__init__(self, upstream_get)
        self.federation_entity = federation_entity
        self.delegation_verifier = TrustMarkDelegationVerifier(upstream_get=upstream_get,
                                                               federation_entity=federation_entity)

    def __call__(self,
                 trust_mark: dict,
                 trust_anchor: str,
                 check_status: Optional[bool] = False,
                 entity_id: Optional[str] = '',
                 ) -> Optional[Message]:
        """
        Verifies that a trust mark is issued by someone in the federation and that
        the signing key is a federation key.

        :param trust_mark: A signed JWT representing a trust mark
        :returns: TrustClaim message instance if OK otherwise None
        """

        _trust_mark_jws = trust_mark["trust_mark"]

        _jws = as_unicode(_trust_mark_jws)
        _jwt = factory(_jws)
        _msg_type = _jwt.jwt.headers.get("typ")
        if not _msg_type or _msg_type != "trust-mark+jwt":
            raise ValueError("Missing or wrong message type")

        payload = _jwt.jwt.payload()
        _trust_mark_msg = message.TrustMark(**payload)
        # Verify that everything that should be there, are there
        try:
            _trust_mark_msg.verify()
        except Expired:  # Has it expired ?
            return None
        except ValueError:  # Not correct delegation ?
            raise

        # Get trust anchor information in order to verify the issuer and if needed the delegator.
        if self.federation_entity:
            _federation_entity = self.federation_entity
        else:
            _federation_entity = get_federation_entity(self)

        trust_anchor_statement = get_verified_trust_anchor_statement(_federation_entity, trust_anchor)

        # Trust mark issuers recognized by the trust anchor
        _trust_mark_issuers = trust_anchor_statement.get("trust_mark_issuers")
        if _trust_mark_issuers is None:  # No trust mark issuers are recognized by the trust anchor
            return None
        _allowed_issuers = _trust_mark_issuers.get(_trust_mark_msg['trust_mark_type'])
        if _allowed_issuers is None:
            return None

        if _allowed_issuers == [] or _trust_mark_msg["iss"] in _allowed_issuers:
            pass
        else:  # The trust mark issuer not trusted by the trust anchor
            logger.warning(
                f'Trust mark issuer {_trust_mark_msg["iss"]} not trusted by the trust anchor for trust mark id:'
                f' {_trust_mark_msg["trust_mark_type"]}')
            return None

        # Now time to verify the signature of the trust mark
        _trust_chains = []
        if _trust_mark_msg["iss"] != trust_anchor:
            _trust_chains = get_verified_trust_chains(_federation_entity, _trust_mark_msg['iss'])
            if not _trust_chains:
                logger.warning(f"Could not find any verifiable trust chains for {_trust_mark_msg['iss']}")
                return None

            if trust_anchor not in [_tc.anchor for _tc in _trust_chains]:
                logger.warning(f'No verified trust chain to the trust anchor: {trust_anchor}')
                return None

        # Now try to verify the signature on the trust_mark
        # should have the necessary keys
        _jwt = factory(_trust_mark_jws)
        keyjar = keyjar_combination(self)

        keys = keyjar.get_jwt_verify_keys(_jwt.jwt)
        if not keys:
            if _trust_mark_msg["iss"] != trust_anchor:
                keyjar = import_jwks(keyjar,
                                     trust_anchor_statement["jwks"],
                                     trust_anchor_statement["iss"])
            else:
                _trust_chains = apply_policies(_federation_entity, _trust_chains)
                keyjar = import_jwks(keyjar,
                                     _trust_chains[0].verified_chain[-1]["jwks"],
                                     _trust_chains[0].iss_path[0])

            keys = keyjar.get_jwt_verify_keys(_jwt.jwt)

        try:
            _mark = _jwt.verify_compact(_trust_mark_jws, keys=keys)
        except Exception as err:
            return None

        _trust_mark_verified = TrustMark(**_mark)

        # Must be issued on delegation
        _owners = trust_anchor_statement.get("trust_mark_owners", {})
        if _owners:
            # Check delegation
            _delegation = self.delegation_verifier(_trust_mark_verified, trust_anchor_statement, _owners)
            if not _delegation:
                return None
            else:
                _trust_mark_verified["__delegation"] = _delegation

        return _trust_mark_verified


class TrustMarkDelegationVerifier(Function):
    """
    The steps are:

    - The delegation MUST be a signed JWT
    - The delegation MUST have a typ header with the value trust-mark-delegation+jwt
    - The delegation MUST have an alg (algorithm) header parameter with a value that is an acceptable JWS signing
    algorithm; it MUST NOT be none
    - The Entity Identifier of the Trust Mark issuer Must match the value of sub in the delegation
    - The Entity Identifier of the Trust Mark owner MUST match the value of iss in the delegation.
    - The current time MUST be after the time represented by the iat (issued at) Claim in the delegation (possibly
    allowing for some small leeway to account for clock skew).
    - The current time MUST be before the time represented by the exp (expiration) Claim in the delegation (possibly
    allowing for some small leeway to account for clock skew).
    - The delegation's signature MUST validate using one of the Trust Mark Owner's keys identified by the value of
    the header parameter kid. The Trust Mark Owner's keys can be found in the trust_mark_owners claim in the Trust
    Anchor's Entity Configuration."""

    def __init__(self, upstream_get: Optional[Callable] = None,
                 federation_entity: Optional[FederationEntity] = None):
        if not upstream_get and not federation_entity:
            raise ValueError("Must have one of upstream_get and federation_entity")
        Function.__init__(self, upstream_get)
        self.federation_entity = federation_entity

    def __call__(self, trust_mark, trust_anchor_statement, owners, **kwargs):
        _delegation_jwt = trust_mark.get('delegation')
        if not _delegation_jwt:
            logger.warning("No delegation claim present")
            return None

        _delegation = factory(_delegation_jwt)
        # Check header
        jwt_sign_alg = _delegation.jwt.headers.get("alg")
        if not jwt_sign_alg or jwt_sign_alg == "none":
            logger.warning("Missing signing algorithm specification or not acceptable algorithm")
            return None
        jwt_type = _delegation.jwt.headers.get("typ")
        if not jwt_type or jwt_type != "trust-mark-delegation+jwt":
            logger.warning("Missing or wrong JWT type")
            return None

        # Get the owners keys from the Trust Anchor Configuration
        tm_owner_info = owners.get(trust_mark["trust_mark_type"])
        if not tm_owner_info:
            logger.warning("No information about the Trust Mark Owner in the Trust Anchors Configuration")
            return None

        _key_jar = KeyJar()
        _key_jar = import_jwks(_key_jar, tm_owner_info['jwks'], tm_owner_info['sub'])
        keys = _key_jar.get_jwt_verify_keys(_delegation.jwt)

        _verified_delegation = _delegation.verify_compact(keys=keys)
        _verified_delegation = TrustMarkDelegation(**_verified_delegation)
        _verified_delegation.verify()

        # object with two parameters 'sub' and 'jwks'
        if tm_owner_info["sub"] != _verified_delegation["iss"]:
            logger.warning(
                f"{_verified_delegation['iss']} not recognized delegator for {trust_mark['trust_mark_type']}")
            return None
        if trust_mark["iss"] != _verified_delegation["sub"]:
            logger.warning(
                f"Issuer {trust_mark['iss']} does not match the sub {_verified_delegation['sub']} in the delegation")
            return None

        return _verified_delegation
