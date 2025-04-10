import logging
from typing import Callable
from typing import Optional

from cryptojwt import KeyJar
from cryptojwt.jws.jws import factory
from idpyoidc.key_import import import_jwks

from fedservice import message
from fedservice.entity import apply_policies
from fedservice.entity.function import Function
from fedservice.entity.function import get_payload
from fedservice.entity.function import get_verified_trust_chains
from fedservice.entity.utils import get_federation_entity
from fedservice.utils import statement_is_expired

logger = logging.getLogger(__name__)


class TrustMarkVerifier(Function):

    def __init__(self, upstream_get: Callable):
        Function.__init__(self, upstream_get)

    def __call__(self,
                 trust_mark: str,
                 trust_anchor: str,
                 check_status: Optional[bool] = False,
                 entity_id: Optional[str] = '',
                 ):
        """
        Verifies that a trust mark is issued by someone in the federation and that
        the signing key is a federation key.

        :param trust_mark: A signed JWT representing a trust mark
        :returns: TrustClaim message instance if OK otherwise None
        """

        payload = get_payload(trust_mark)
        _trust_mark = message.TrustMark(**payload)
        # Verify that everything that should be there, are there
        _trust_mark.verify()

        # Has it expired ?
        if statement_is_expired(_trust_mark):
            return None

        # deal with delegation
        if 'delegation' in _trust_mark:
            _delegation = self.verify_delegation(_trust_mark, trust_anchor)
            if not _delegation:
                logger.warning("Could not verify the delegation")

        # Get trust chain
        # _federation_entity = get_federation_entity(self)
        # _chains, entity_conf = collect_trust_chains(_federation_entity, _trust_mark['iss'])
        # _trust_chains = verify_trust_chains(_federation_entity, _chains, entity_conf)
        _trust_chains = get_verified_trust_chains(self, _trust_mark['iss'])
        if not _trust_chains:
            logger.warning(f"Could not find any verifiable trust chains for {_trust_mark['iss']}")
            return None

        if trust_anchor not in [_tc.anchor for _tc in _trust_chains]:
            logger.warning(f'No verified trust chain to the trust anchor: {trust_anchor}')
            return None

        # Now try to verify the signature on the trust_mark
        # should have the necessary keys
        _federation_entity = get_federation_entity(self)
        _jwt = factory(trust_mark)
        keyjar = _federation_entity.get_attribute('keyjar')

        keys = keyjar.get_jwt_verify_keys(_jwt.jwt)
        if not keys:
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

        if trust_mark['trust_mark_id'] not in _entity_configuration['trust_mark_issuers']:
            return None
        if trust_mark['trust_mark_id'] not in _entity_configuration['trust_mark_owners']:
            return None

        _delegation = factory(trust_mark['delegation'])
        tm_owner_info = _entity_configuration['trust_mark_owners'][trust_mark['trust_mark_id']]
        _key_jar = KeyJar()
        _key_jar = import_jwks(_key_jar, tm_owner_info['jwks'], tm_owner_info['sub'])
        keys = _key_jar.get_jwt_verify_keys(_delegation.jwt)
        return _delegation.verify_compact(keys=keys)
