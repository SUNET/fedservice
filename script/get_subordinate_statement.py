#!/usr/bin/env python3
import json

from pygments import highlight
from pygments.formatters.terminal import TerminalFormatter
from pygments.lexers.data import JsonLexer

from fedservice.entity.function.trust_chain_collector import unverified_entity_statement
from fedservice.entity.function.trust_chain_collector import verify_self_signed_signature
from fedservice.utils import make_federation_entity

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-k', "--insecure", action='store_true')
    parser.add_argument('-f', "--format", action='store_true')
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
                                               trust_anchors=trust_anchors)
    if args.insecure:
        federation_entity.context.keyjar.httpc_params = {"verify": False}

    _collector = federation_entity.get_function("trust_chain_collector")

    _info = None

    # Get the entity configuration for the superior
    _jws = _collector.get_entity_configuration(args.superior)
    superior_entity_configuration = verify_self_signed_signature(_jws)

    # Pick out the fetch endpoint
    _fetch_endpoint = superior_entity_configuration["metadata"]["federation_entity"]["federation_fetch_endpoint"]

    # Ask the superior for the subordinate statement
    _jws = _collector.get_entity_statement(fetch_endpoint=_fetch_endpoint,
                                           issuer=args.superior,
                                           subject=args.entity_id)
    # Don't try to verify the signatures
    entity_statement = unverified_entity_statement(_jws)
    json_str = json.dumps(entity_statement, indent=2)
    print(20 * "=" + f" Subordinate Statement about {args.entity_id} from {args.superior} " + 20 * "=")
    if args.format:
        print(highlight(json_str, JsonLexer(), TerminalFormatter()))
    else:
        print(json_str)
