#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path

from idpyoidc.util import load_config_file


def parse_args():
    parser = argparse.ArgumentParser(
        description="Extract Trust Mark types from a Trust Mark Issuer config and output as JSON."
    )
    parser.add_argument("directory", help="Path to the directory containing conf.json")
    return parser.parse_args()


def main():
    args = parse_args()

    conf_path = Path(args.directory) / "conf.json"
    if not conf_path.is_file():
        sys.exit(f"ERROR: Config file not found: {conf_path}")

    cnf = load_config_file(str(conf_path))

    entity_id = cnf["entity"]["entity_id"]
    _ids = list(
        cnf["entity"]["trust_mark_entity"]["kwargs"]["trust_mark_specification"].keys()
    )

    print(json.dumps({entity_id: _ids}))


if __name__ == "__main__":
    main()
