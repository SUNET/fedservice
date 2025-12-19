#!/usr/bin/env python3
import json

from idpyoidc.storage.abfile import AbstractFileSystem

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(dest="target")
    args = parser.parse_args()

    if not args.target:
        print("Need target directory")

    _ab_dict = AbstractFileSystem(fdir=args.target,
                                  key_conv="idpyoidc.util.Base64",
                                  value_conv="idpyoidc.util.JSON")

    for key, val in _ab_dict.items():
        print(key)
        print(val)
        print()
