#!/usr/bin/env python3
import json
from typing import Optional

from fedservice.entity import get_verified_trust_chains
from fedservice.entity.function.trust_chain_collector import verify_self_signed_signature
from fedservice.utils import make_federation_entity


def get_entity_configuration(federation_entity, entity_id: str):
    _collector = federation_entity.get_function("trust_chain_collector")
    # Read the entity configuration
    _jws = _collector.get_entity_configuration(entity_id)
    # Verify the self signed signature
    return verify_self_signed_signature(_jws)


def do_subordinates(federation_entity, entity_id: str, superior: Optional[str] = "") -> dict:
    entity_configuration = get_entity_configuration(federation_entity, entity_id)
    if superior:
        if superior not in entity_configuration["authority_hints"]:
            print(f"ERROR! {superior} not in authority_hints for {entity_id}")

    if "federation_list_endpoint" in entity_configuration["metadata"]["federation_entity"]:
        res = {}
        endpoint = entity_configuration["metadata"]["federation_entity"]["federation_list_endpoint"]
        # Ask the superior for the subordinates
        _list_response = federation_entity.client.do_request('list', endpoint=endpoint)
        if _list_response:
            for sub in _list_response:
                res.update(do_subordinates(federation_entity, sub, entity_id))
        return res
    else:
        return {entity_id: {}}

def find_trust_chain(federation_entity, item, trust_anchor):
    for entity_id, subordinates in item.items():
        trust_chains = get_verified_trust_chains(federation_entity, entity_id)
        if not trust_chains:
            print(f"[{entity_id}] Could not find any trust chain")
        _trust_chain_ta = [t for t in trust_chains if t.anchor == trust_anchor]
        if not _trust_chain_ta:
            print(f"[{entity_id}] Could not find a trust chain that ended in a TA I trust")
        else:
            print(f"[{entity_id}] Found a valid trust chain")

        if subordinates:
            find_trust_chain(federation_entity, subordinates, trust_anchor)

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-c', "--trust_chains", action='store_true')
    parser.add_argument('-k', "--insecure", action='store_true')
    parser.add_argument(dest="root_entity_id")
    args = parser.parse_args()

    if not args.root_entity_id:
        print("Need an entity_id to work with")

    federation_entity = make_federation_entity(entity_id="https://localhost")

    entity_configuration = get_entity_configuration(federation_entity, args.root_entity_id)
    federation_entity.function.trust_chain_collector.trust_anchors = {
        args.root_entity_id: entity_configuration["jwks"]
    }
    federation_entity.context.keyjar.import_jwks(entity_configuration["jwks"], args.root_entity_id, )

    if args.insecure:
        federation_entity.context.keyjar.httpc_params = {"verify": False}

    res = do_subordinates(federation_entity, entity_id=args.root_entity_id)

    print(res)

    if args.trust_chains:
        print(40 * "=")
        find_trust_chain(federation_entity, res, args.root_entity_id)