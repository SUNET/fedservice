#!/usr/bin/env python3
import json

from fedservice.defaults import federation_services
from fedservice.entity.function import get_entity_endpoint
from fedservice.utils import make_federation_entity

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-k', "--insecure", action='store_true')
    parser.add_argument('-t', "--trust_anchors_file")
    parser.add_argument('-s', "--superior")
    parser.add_argument(dest="entity_id")
    args = parser.parse_args()

    if not args.entity_id:
        print("Need an entity_id to work with")

    if args.trust_anchors_file:
        trust_anchors = json.loads(open(args.trust_anchors_file).read())
    else:
        trust_anchors = {}

    federation_entity = make_federation_entity(entity_id="https://localhost",
                                               services=federation_services("entity_configuration", "list",
                                                                            "entity_statement"),
                                               trust_anchors=trust_anchors)
    if args.insecure:
        federation_entity.context.keyjar.httpc_params = {"verify": False}
        federation_entity.client.httpc_params = {"verify": False}

    # Need to find the listing endpoint
    endpoint = get_entity_endpoint(federation_entity, args.entity_id, "federation_entity",
                                   "federation_list_endpoint")

    # Ask the superior for the subordinates statement
    _response = federation_entity.client.do_request('list', endpoint=endpoint)

    # Don't try to verify the signatures
    print(20 * "=" + f" Subordinates of {args.entity_id} : {_response} " + 20 * "=")
