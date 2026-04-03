#!/usr/bin/env python3
import argparse
import contextlib
import os
from pathlib import Path

from idpyoidc.storage.abfile import AbstractFileSystem
from idpyoidc.util import load_config_file

from fedservice import get_payload
from fedservice.utils import make_federation_entity


@contextlib.contextmanager
def pushd(new_dir: Path):
    prev = Path.cwd()
    os.chdir(new_dir)
    try:
        yield
    finally:
        os.chdir(prev)

def _get_tmi(fe):
    # Handle both layouts seen in fedservice
    return getattr(fe, "trust_mark_entity", None) or getattr(fe, "server").trust_mark_entity


def main() -> int:
    p = argparse.ArgumentParser(
        description="Create a Trust Mark with a fedservice Trust Mark Issuer and optionally store it in abfile.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-d", "--dir_name", required=True, help="Directory containing conf.json")
    p.add_argument("-e", "--entity_id", required=True, help="Subject entity_id the Trust Mark applies to")
    p.add_argument("-m", "--trust_mark_type", required=True, help="Trust Mark type identifier (URI)")
    p.add_argument("-o", "--out", help="Write the compact JWS to this file instead of stdout")
    p.add_argument(
        "--base-dir",
        help="Working directory to resolve relative paths in conf.json. Defaults to the directory that contains conf.json.",
    )
    p.add_argument(
        "--store-dir",
        help="If set, store the Trust Mark in this abfile directory (JSON values).",
    )


    args = p.parse_args()

    conf_path = Path(args.dir_name, "conf.json").resolve()
    base_dir = Path(args.base_dir).resolve() if args.base_dir else Path(args.dir_name).resolve().parent

    print(f"DIR: {base_dir}")

    with pushd(base_dir):
        cnf = load_config_file(str(conf_path))
        fe = make_federation_entity(**cnf["entity"])

        tmi = _get_tmi(fe)
        trust_mark = tmi.create_trust_mark(args.trust_mark_type, args.entity_id)

    payload = get_payload(trust_mark)
    iss = payload.get("iss")
    iat = payload.get("iat")

    if args.store_dir:
        fdir = Path(args.store_dir).resolve()
        fdir.mkdir(parents=True, exist_ok=True)

        key = f"iss={iss}:trust_mark_type={args.trust_mark_type}:iat={iat}"

        value = {
            "trust_mark": trust_mark,
            "trust_mark_type": args.trust_mark_type,
        }

        store = AbstractFileSystem(
            fdir=str(fdir),
            key_conv="idpyoidc.util.Base64",
            value_conv="idpyoidc.util.JSON",
        )
        store[key] = value
        print(f"Stored Trust Mark in abfile. dir={fdir} key={key}")

    if args.out:
        Path(args.out).write_text(trust_mark + "\n", encoding="utf-8")
    else:
        print(trust_mark)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
