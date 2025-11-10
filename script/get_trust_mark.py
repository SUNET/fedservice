#!/usr/bin/env python3
import json

import requests

from fedservice.defaults import federation_services
from fedservice.entity.function import get_entity_endpoint
from fedservice.utils import make_federation_entity

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-k', "--insecure", action='store_true')
    parser.add_argument('-f', "--format", action='store_true')
    parser.add_argument('-t', "--trust_anchors")
    parser.add_argument('-i', "--trust_mark_type")
    parser.add_argument('-s', "--subject")
    parser.add_argument(dest="entity_id")
    args = parser.parse_args()

    if not args.entity_id:
        print("Need an entity_id to work with")

    trust_anchors = json.loads(open(args.trust_anchors).read())

    federation_entity = make_federation_entity(entity_id="https://localhost",
                                               services=federation_services("entity_configuration", "trust_mark",
                                                                            "entity_statement"),
                                               trust_anchors=trust_anchors)

    if args.insecure:
        _param = {"verify": False}
        federation_entity.keyjar.httpc_params = _param
        federation_entity.httpc_params = _param
        federation_entity.client.httpc_params = _param

    httpc = getattr(federation_entity, "httpc", None)
    if not httpc:
        httpc = requests

    # Need to find the trust mark issuer Trust Mark Endpoint
    endpoint = get_entity_endpoint(federation_entity, args.entity_id, "federation_entity",
                                   "federation_trust_mark_endpoint")

    # federation_entity.client.context.issuer = args.entity_id
    _response = federation_entity.client.do_request("trust_mark",
                                                    request_args={
                                                        "trust_mark_type": args.trust_mark_type,
                                                        "sub": args.subject
                                                    },
                                                    endpoint=endpoint)
    #result = _service.parse_response(response)
    print(f"Trust mark claims: {_response}")
