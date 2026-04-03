import logging
from typing import Callable
from typing import Optional

from cryptojwt import KeyJar
from cryptojwt.exception import Expired
from cryptojwt.jws.jws import factory

from fedservice import get_payload
from fedservice.entity import FederationEntity
from idpyoidc.key_import import import_jwks
from idpyoidc.message import Message

from fedservice import message
from fedservice.entity import apply_policies
from fedservice.entity.function import Function
from fedservice.entity.function import get_verified_trust_chains
from fedservice.entity.function import verify_signature
from fedservice.entity.function.trust_anchor import get_verified_trust_anchor_statement
from fedservice.entity.utils import get_federation_entity
from idpyoidc.message.oidc import EXPError

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

    def check_delegation(self, trust_anchor_statement, trust_mark) -> bool:
        _owners = trust_anchor_statement.get("trust_mark_owners", {})
        if _owners:
            _delegator = _owners.get(trust_mark["trust_mark_type"])
        else:
            _delegator = None

        if "delegation" in trust_mark:
            # object with two parameters 'sub' and 'jwks'
            if _delegator["sub"] != trust_mark["__delegation"]["iss"]:
                logger.warning(
                    f"{trust_mark['__delegation']['iss']} not recognized delegator for {trust_mark['trust_mark_type']}")
                return False
            try:
                _token = verify_signature(trust_mark["delegation"], _delegator["jwks"], _delegator["sub"])
            except Exception as err:
                logger.exception("Verify delegation signature failed")
                return False

            # Might want to put _token in trust_mark[verified_claim_name("delegation")]
        else:
            if _delegator:
                return False

        return True

    def __call__(self,
                 trust_mark: str,
                 trust_anchor: str,
                 check_status: Optional[bool] = False,
                 entity_id: Optional[str] = None,
                 outer_trust_mark_type: Optional[str] = None
                 ) -> Optional[Message]:
        """
        Verifies that a trust mark is issued by someone in the federation and that
        the signing key is a federation key.

        :param trust_mark: A signed JWT representing a trust mark
        :returns: TrustClaim message instance if OK otherwise None
        """

        payload = get_payload(trust_mark)
        _trust_mark = message.TrustMark(**payload)
        # Verify that everything that should be there, are there
        try:
            _trust_mark.verify(entity_id=entity_id)
        except EXPError:  # Has it expired ?
            return None
        except ValueError:  # Not correct delegation ?
            raise

        if outer_trust_mark_type is not None and outer_trust_mark_type != _trust_mark.get("trust_mark_type"):
            logger.warning(
                f"Trust Mark type mismatch. outer={outer_trust_mark_type} inner={_trust_mark.get('trust_mark_type')} "
                f"iss={_trust_mark.get('iss')} sub={_trust_mark.get('sub')}"
            )
            return None

        # Get trust anchor information in order to verify the issuer and if needed the delegator.
        if self.federation_entity:
            _federation_entity = self.federation_entity
        else:
            _federation_entity = get_federation_entity(self)

        trust_anchor_statement = get_verified_trust_anchor_statement(_federation_entity, trust_anchor)

        # Check delegation
        if self.check_delegation(trust_anchor_statement, _trust_mark) == False:
            return None

        # Trust mark issuers recognized by the trust anchor
        _trust_mark_issuers = trust_anchor_statement.get("trust_mark_issuers")
        if _trust_mark_issuers is None:  # No trust mark issuers are recognized by the trust anchor
            return None
        _allowed_issuers = _trust_mark_issuers.get(_trust_mark['trust_mark_type'])
        if _allowed_issuers is None:
            return None

        if _allowed_issuers == [] or _trust_mark["iss"] in _allowed_issuers:
            pass
        else:  # The trust mark issuer not trusted by the trust anchor
            logger.warning(
                f'Trust mark issuer {_trust_mark["iss"]} not trusted by the trust anchor for trust mark type: '
                f'{_trust_mark["trust_mark_type"]}')
            return None

        # Now time to verify the signature of the trust mark
        _trust_chains = []
        if _trust_mark["iss"] != trust_anchor:
            _trust_chains = get_verified_trust_chains(_federation_entity, _trust_mark['iss'])
            if not _trust_chains:
                logger.warning(f"Could not find any verifiable trust chains for {_trust_mark['iss']}")
                return None

            if trust_anchor not in [_tc.anchor for _tc in _trust_chains]:
                logger.warning(f'No verified trust chain to the trust anchor: {trust_anchor}')
                return None

        # Now try to verify the signature on the trust_mark
        # should have the necessary keys
        _jwt = factory(trust_mark)
        keyjar = _federation_entity.get_attribute('keyjar')

        keys = keyjar.get_jwt_verify_keys(_jwt.jwt)
        if not keys:
            if _trust_mark["iss"] != trust_anchor:
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
            _mark = _jwt.verify_compact(trust_mark, keys=keys)
        except Exception as err:
            return None
        else:
            return _mark

    def verify_delegation(self, trust_mark, trust_anchor_id):
        _federation_entity = get_federation_entity(self)
        _collector = _federation_entity.function.trust_chain_collector
        # Deal with the delegation
        _entity_configuration = _collector.get_verified_self_signed_entity_configuration(trust_anchor_id)

        if trust_mark['trust_mark_type'] not in _entity_configuration['trust_mark_issuers']:
            return None
        if trust_mark['trust_mark_type'] not in _entity_configuration['trust_mark_owners']:
            return None

        _delegation = factory(trust_mark['delegation'])
        tm_owner_info = _entity_configuration['trust_mark_owners'][trust_mark['trust_mark_type']]
        _key_jar = KeyJar()
        _key_jar = import_jwks(_key_jar, tm_owner_info['jwks'], tm_owner_info['sub'])
        keys = _key_jar.get_jwt_verify_keys(_delegation.jwt)
        return _delegation.verify_compact(keys=keys)
