import logging
from typing import Callable
from typing import List
from typing import Optional
from typing import Set

from cryptojwt.jws.jws import factory
from cryptojwt.jws.utils import alg2keytype
from cryptojwt.jwt import JWT
from cryptojwt.key_jar import KeyJar
from idpyoidc.impexp import ImpExp
from idpyoidc.key_import import import_jwks

from fedservice import DEFAULT_SKEW
from fedservice.entity.utils import get_federation_entity
from fedservice.entity_statement.statement import TrustChain
from fedservice.message import EntityConfiguration
from fedservice.message import ExplicitRegistrationResponse
from fedservice.message import SubordinateStatement

logger = logging.getLogger(__name__)

Class_map = {
    "entity_configuration": EntityConfiguration,
    "subordinate_statement": SubordinateStatement,
    "registration_response": ExplicitRegistrationResponse
}


def unverified_entity_statement(signed_jwt):
    _jws = factory(signed_jwt)
    return _jws.jwt.payload()


def verify_entity_statement(signed_jwt, sub, skew=DEFAULT_SKEW, msg_type: Optional[str] = "", **kwargs):
    """

    :param signed_jwt: The Entity Statement as a signed JWT
    :param sub: The subject the Entity Statement should refer to
    :param typ: Type of Entity Statement (entity_configuration, subordinate_statement, registration_response)
    :return:
    """
    _jws = factory(signed_jwt)
    if not _jws:
        raise ValueError(f"Not a proper signed JWT: {signed_jwt}")

    typ = _jws.jwt.headers.get('typ')
    if typ:
        if typ != "entity-statement+jwt":
            raise ValueError(f"Wrong Entity Statement type {typ}")
    else:
        raise ValueError("Entity Statement type not properly set")

    payload = _jws.jwt.payload()

    if payload["sub"] != sub:
        raise ValueError("Wrong subject in the Entity Statement")

    jwt_args = {}
    keyjar = kwargs.get("keyjar")
    if keyjar:
        pass
    else:
        keyjar = KeyJar()
        keyjar = import_jwks(keyjar, payload['jwks'], payload['iss'])

        alg = _jws.jwt.headers.get('alg')
        if alg:
            if not keyjar.get_signing_key(alg2keytype(alg), sub):
                return ValueError("Signing algorithm does not match any key in the JWKS")
        else:
            raise ValueError("Entity Statement: no signing algorithm set")
        jwt_args["sign_alg"] = alg

        kid = _jws.jwt.headers.get('kid')
        if kid:
            if not keyjar.get_signing_key(alg2keytype(alg), sub, kid):
                return ValueError("'kid' does not match any key in the JWKS")
        else:
            raise ValueError("Entity Statement: no 'kid' set")

    # There MUST be an iss
    iss = payload.get('iss')
    if not iss:
        raise ValueError("Missing 'iss'")

    _jwt = JWT(key_jar=keyjar, **jwt_args)
    _val = _jwt.unpack(signed_jwt)

    args = {}
    if msg_type:
        _es = Class_map[msg_type](**_val)
    else:  # Best effort
        if iss == sub:  # Entity Configuration
            _es = EntityConfiguration(**_val)
        else:
            _es = SubordinateStatement(**_val)

    _es.verify(skew=skew, **args)

    return _es


def get_endpoint(endpoint_type, config):
    _fe = config['metadata']['federation_entity']
    return _fe.get(f"federation_{endpoint_type}_endpoint")


def verify_self_signed_signature(token):
    """
    Verify signature using only keys in the entity statement.
    Will raise exception if signature verification fails.

    :param token: Signed JWT
    :return: Payload of the signed JWT
    """

    payload = unverified_entity_statement(token)
    keyjar = KeyJar()
    keyjar = import_jwks(keyjar, payload['jwks'], payload['iss'])

    _jwt = JWT(key_jar=keyjar)
    _val = _jwt.unpack(token)
    _val["_jws"] = token
    return _val


def verify_signature(token, jwks, iss):
    _keyjar = KeyJar()
    _keyjar = import_jwks(_keyjar, jwks, iss)
    _jwt = JWT(key_jar=_keyjar)
    return _jwt.unpack(token)


def tree2chains(unit):
    res = []
    for issuer, branch in unit.items():
        if branch is None:
            res.append([])
            continue

        (statement, unit) = branch
        if not unit:
            res.append([statement])
            continue

        _lists = tree2chains(unit)
        for l in _lists:
            l.append(statement)

        if not res:
            res = _lists
        else:
            res.extend(_lists)
    return res


def collect_trust_chains(unit,
                         entity_id: str,
                         signed_entity_configuration: Optional[str] = "",
                         stop_at: Optional[str] = "",
                         authority_hints: Optional[list] = None):
    _federation_entity = get_federation_entity(unit)

    _chains = _federation_entity.trust_chain.get(entity_id)
    if _chains:
        # Are they still active ?
        pass

    _collector = _federation_entity.function.trust_chain_collector

    # Collect the trust chains
    if signed_entity_configuration:
        entity_configuration = verify_self_signed_signature(signed_entity_configuration)
        if authority_hints:
            entity_configuration["authority_hints"] = authority_hints
        tree = _collector.collect_tree(entity_id, entity_configuration, stop_at=stop_at)
    else:
        try:
            _collector_response = _collector(entity_id, stop_at=stop_at)
        except Exception as err:
            logger.error(f"Trust chain collection failed {err}")
            raise (err)
        if _collector_response:
            tree, signed_entity_configuration = _collector_response
        else:
            tree = None

    if tree:
        chains = tree2chains(tree)
        logger.debug("%d chains", len(chains))
        _federation_entity.trust_chain[entity_id] = chains
        return chains, signed_entity_configuration
    elif tree == {}:
        return [], signed_entity_configuration
    else:
        return [], None


def verify_trust_chains(unit, chains: List[List[str]], *entity_statements):
    #
    _verifier = get_federation_entity(unit).function.verifier

    logger.debug("verify_trust_chains")
    res = []
    for c in chains:
        if entity_statements:
            c.extend(entity_statements)
        trust_chains = _verifier(c)
        if trust_chains:
            res.extend(trust_chains)
    return res


def verify_trust_chain(unit, chain: List[str]):
    #
    _verifier = get_federation_entity(unit).function.verifier

    logger.debug("verify_trust_chain")
    return _verifier(chain)


def verify_trust_chain_return_chain(unit, chain: List[str]):
    #
    _verifier = get_federation_entity(unit).function.verifier

    logger.debug("verify_trust_chain")
    return _verifier(chain)


def apply_policies(unit, trust_chains):
    """
    Goes through the collected trust chains, verifies them and applies policies.

    :param unit: A Unit instance
    :param trust_chains: List of TrustChain instances
    :return: List of processed TrustChain instances
    """
    _policy_applier = get_federation_entity(unit).function.policy

    res = []
    for trust_chain in trust_chains:
        _policy_applier(trust_chain)
        res.append(trust_chain)
    return res


class Function(ImpExp):

    def __init__(self, upstream_get: Callable):
        ImpExp.__init__(self)
        self.upstream_get = upstream_get


def get_verified_trust_chains(unit, entity_id: str, stop_at: Optional[str] = "") -> Optional[List[TrustChain]]:
    chains, leaf_ec = collect_trust_chains(unit, entity_id, stop_at=stop_at)
    if len(chains) == 0:
        return []

    trust_chains = verify_trust_chains(unit, chains, leaf_ec)
    trust_chains = apply_policies(unit, trust_chains)
    return trust_chains


def get_entity_endpoint(unit, entity_id, metadata_type, metadata_parameter):
    _federation_entity = get_federation_entity(unit)
    if entity_id in _federation_entity.trust_anchors:
        # Fetch Entity Configuration
        _ec = _federation_entity.client.do_request("entity_configuration", entity_id=entity_id)
        return _ec["metadata"][metadata_type][metadata_parameter]
    else:
        trust_chains = get_verified_trust_chains(unit, entity_id)
        # pick one
        if trust_chains:
            return trust_chains[0].metadata[metadata_type][metadata_parameter]
        else:
            return ""


def get_verified_jwks(unit, _signed_jwks_uri):
    # Fetch a signed JWT that contains a JWKS.
    # Verify the signature on the JWS with a federation key
    # To be implemented
    return None


class PolicyError(Exception):
    pass


def collect_trust_chain_by_authority_hints(unit, entity_id: str, authority_hints: List[str], trust_anchor: str):
    """

    :param unit: A Unit instance
    :param entity_id: The entity_id of the leaf
    :param authority_hints: The list of authority_hints from the leaf to the TA subordinate
    :return: A list of EntityStatements or None
    """
    _federation_entity = get_federation_entity(unit)
    _collector = _federation_entity.function.trust_chain_collector

    chain = []

    # Pick up the Entity Configuration for the leaf entity
    entity_config, signed_entity_config = _collector._get_entity_configuration(entity_id)
    _subordinate = entity_config["iss"]

    _entity_config = {}
    for hint in authority_hints:
        if hint in entity_config:
            # Get the superior's entity configuration
            _entity_config, _signed_entity_config = _collector._get_entity_configuration(hint)
            # Get the Subordinate statement
            _subordinate_statement = _collector._get_entity_statement(hint, _subordinate)
            statement = unverified_entity_statement(_subordinate_statement)
            chain.append(statement)

    if trust_anchor not in _entity_config:
        raise ValueError("Trust chain did not end in expected Trust Anchor")

    return chain


def pick_trust_anchors(unit, server_entity_id) -> Optional[List[str]]:
    _federation_entity = get_federation_entity(unit)
    _collector = _federation_entity.function.trust_chain_collector

    # Pick up the Entity Configuration for the server entity
    entity_config, signed_entity_config = _collector.get_entity_configuration(server_entity_id)

    ta_hints = entity_config.get('trust_anchor_hints')
    if ta_hints:
        usable_ta = set(_collector.trust_anchors.keys()).intersection(set(ta_hints))
        if usable_ta:
            return list(usable_ta)
    else:  # Try to find a chain from the server to a trusted TA
        for ta in _collector.trust_anchors.keys():
            chains = get_verified_trust_chains(unit, server_entity_id, stop_at=ta)
            if chains:
                return [ta]  # Only need one
    return None

def get_federation_entity_keyjar(item):
    _fed_entity = get_federation_entity(item)
    return _fed_entity.context.keyjar