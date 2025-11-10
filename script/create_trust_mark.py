#!/usr/bin/env python3
import argparse
import os
from pathlib import Path
import contextlib

from idpyoidc.util import load_config_file

from fedservice.utils import \
    make_federation_entity  # type: ignore[attr-defined]


@contextlib.contextmanager
def pushd(new_dir: Path):
    prev = Path.cwd()
    os.chdir(new_dir)
    try:
        yield
    finally:
        os.chdir(prev)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Create a Trust Mark with a fedservice Trust Mark Issuer.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-d", "--dir_name", required=True, help="Directory containing conf.json")
    p.add_argument("-e", "--entity_id", required=True, help="Subject entity_id the Trust Mark applies to")
    p.add_argument("-m", "--trust_mark_type", required=True, help="Trust Mark type identifier (URI)")
    p.add_argument("--base-dir", help="Working directory to resolve relative paths in conf.json. "
                                      "Defaults to the directory that contains conf.json.")
    p.add_argument("-o", "--out", help="Write JWT to this file instead of stdout")
    args = p.parse_args()

    conf_path = Path(args.dir_name, "conf.json").resolve()
    base_dir = Path(args.base_dir).resolve() if args.base_dir else Path(args.dir_name).resolve().parent

    print(f"DIR: {base_dir}")
    with pushd(base_dir):
        cnf = load_config_file(str(conf_path))
        fe = make_federation_entity(**cnf["entity"])

        # Trust Mark Issuer interface (handle both layouts)
        tmi = getattr(fe, "trust_mark_entity", None) or getattr(fe, "server").trust_mark_entity
        jwt_compact = tmi.create_trust_mark(args.trust_mark_type, args.entity_id)

    if args.out:
        Path(args.out).write_text(jwt_compact + "\n", encoding="utf-8")
    else:
        print(jwt_compact)


if __name__ == "__main__":
    main()
