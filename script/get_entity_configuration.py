#!/usr/bin/env python3
import json
import sys

from pygments import highlight
from pygments.formatters.terminal import TerminalFormatter
from pygments.lexers.data import JsonLexer

from fedservice.entity.function.trust_chain_collector import verify_self_signed_signature
from fedservice.utils import make_federation_entity

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-k', "--insecure", action='store_true')
    parser.add_argument('-f', "--format", action='store_true')
    parser.add_argument('-t', "--trust_anchors_file")
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
        federation_entity.keyjar.httpc_params = {"verify": False}

    _collector = federation_entity.get_function("trust_chain_collector")

    # Read the entity configuration
    _jws = _collector.get_entity_configuration(args.entity_id)
    # Verify the self signed signature
    entity_configuration = verify_self_signed_signature(_jws)
    # Print
    json_str = json.dumps(entity_configuration, indent=2)
    print(20 * "=" + f" Entity Configuration for {args.entity_id} " + 20 * "=", file=sys.stderr)
    if args.format:
        print(highlight(json_str, JsonLexer(), TerminalFormatter()))
    else:
        print(json_str)
