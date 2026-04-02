#!/usr/bin/env python3
import argparse
import json
import sys

from idpyoidc.storage.abfile import AbstractFileSystem


def parse_args():
    parser = argparse.ArgumentParser(description="Update TA trust_mark_issuers AbstractFileSystem store")
    parser.add_argument("-s", "--source", required=True, help="Path to JSON file or '-' for stdin")
    parser.add_argument("-t", "--target", required=True, help="TA store dir (e.g. trust_anchor/trust_mark_issuers)")
    parser.add_argument("--remove", action="store_true", help="Remove issuer from listed trust_mark_ids instead of adding")
    parser.add_argument("--drop-empty", action="store_true",
                   help="If a removal would leave a Trust Mark type with an empty issuer list, "
                        "delete that key instead of writing an empty list")
    return parser.parse_args()


def read_json(source: str):
    if source == "-":
        return json.load(sys.stdin)
    with open(source, "r", encoding="utf-8") as fp:
        return json.load(fp)


def main():
    args = parse_args()

    store = AbstractFileSystem(
        fdir=args.target,
        key_conv="idpyoidc.util.Base64",
        value_conv="idpyoidc.util.JSON",
    )

    data = read_json(args.source)

    changes = 0
    would_be_empty = []
    for issuer, mark_ids in data.items():
        for tm_id in mark_ids:
            current = store.get(tm_id, [])
            if args.remove:
                if issuer in current:
                    next_list = [i for i in current if i != issuer]
                    if not next_list:
                        # empty would mean “anyone can issue”. Avoid unless explicitly allowed.
                        if args.drop_empty:
                            # __delitem__ expects the serialized key, so serialize it explicitly.
                            del store[store.key_conv.serialize(tm_id)]
                            changes += 1
                        else:
                            would_be_empty.append(tm_id)
                        store[tm_id] = next_list
                        changes += 1
            else:
                if issuer not in current:
                    current.append(issuer)
                    store[tm_id] = current
                    changes += 1
    if would_be_empty:
        tms = ", ".join(would_be_empty)
        print(
            f"Refusing to write empty issuer lists for: {tms}. "
            f"Use --remove with --drop-empty to delete those keys instead.."
        )

    print(f"Applied {changes} change(s).")


if __name__ == "__main__":
    main()
