#!/usr/bin/env python3
import argparse
import json
import sys

from idpyoidc.storage.abfile import AbstractFileSystem


def parse_args():
    parser = argparse.ArgumentParser(description="Load Entity Configuration into an AbstractFileSystem store.")
    parser.add_argument("-s", "--source", required=True, help="Path to JSON file or '-' for stdin")
    parser.add_argument("-t", "--target", required=True, help="AbstractFilesystem target directory")
    parser.add_argument("-r", "--trust_anchor_info", action="store_true", help="Store Trust Anchor")
    parser.add_argument("-u", "--subordinate_info", action="store_true", help="Store Subordinate info")

    return parser.parse_args()


def read_json(source: str):
    if source == "-":
        return json.load(sys.stdin)
    with open(source, "r", encoding="utf-8") as fp:
        return json.load(fp)


def main():
    args = parse_args()

    entity_configuration = read_json(args.source)

    info = None
    if args.trust_anchor_info and not args.subordinate_info:
        info = {entity_configuration["sub"]: entity_configuration["jwks"]}
    elif args.subordinate_info and not args.trust_anchor_info:
        _md = entity_configuration.get("metadata", {})
        _sub_info = {
            "entity_types": list(_md.keys()),
            "jwks": entity_configuration["jwks"],
        }

        # Publishing the list endpoint makes this an intermediate
        _fe_md = _md.get("federation_entity", {})
        if isinstance(_fe_md, dict) and "federation_list_endpoint" in _fe_md:
            _sub_info["intermediate"] = True

        info = {entity_configuration["sub"]: _sub_info}
    elif args.subordinate_info and args.trust_anchor_info:
        print("You can only do one at the time!!", file=sys.stderr)
        sys.exit(2)
    else:
        print("Pass -r or -u.", file=sys.stderr)
        sys.exit(2)

    store = AbstractFileSystem(
        fdir=args.target,
        key_conv="idpyoidc.util.Base64",
        value_conv="idpyoidc.util.JSON",
    )

    wrote = 0
    for key, val in info.items():
        store[key] = val
        wrote += 1

    print(f"Done. {wrote} entr{'y' if wrote == 1 else 'ies'} written to {args.target}.")


if __name__ == "__main__":
    main()
