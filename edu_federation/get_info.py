#!/usr/bin/env python3
import json

from fedservice.entity.function.trust_chain_collector import verify_self_signed_signature
from fedservice.utils import make_federation_entity

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-k', "--insecure", action='store_true')
    parser.add_argument('-t', "--trust_anchor_info", action='store_true')
    parser.add_argument('-s', "--subordinate_info", action="store_true")
    parser.add_argument(dest="entity_id")
    args = parser.parse_args()

    if not args.entity_id:
        print("Need an entity_id to work with")

    federation_entity = make_federation_entity(entity_id="https://localhost")

    if args.insecure:
        federation_entity.context.keyjar.httpc_params = {"verify": False}

    _collector = federation_entity.get_function("trust_chain_collector")
    _payload, _jws = _collector.get_entity_configuration(args.entity_id)
    entity_configuration = verify_self_signed_signature(_jws)

    # must have one of them not both

    info = None
    if args.trust_anchor_info and not args.subordinate_info:
        info = {args.entity_id: entity_configuration["jwks"]}
    elif args.subordinate_info and not args.trust_anchor_info:
        _sub_info = {
            "entity_types": list(entity_configuration["metadata"].keys()),
            "jwks": entity_configuration["jwks"]
        }
        # Publishing the list endpoint makes this an intermediate
        if "federation_list_endpoint" in entity_configuration["metadata"]["federation_entity"]:
            _sub_info["intermediate"] = True
        info = {args.entity_id: _sub_info}
    elif args.subordinate_info and args.trust_anchor_info:
        print("You can only do one at the time!!")
    else:
        print("What do you expect me to do ??")

    if info:
        print(json.dumps(info))
