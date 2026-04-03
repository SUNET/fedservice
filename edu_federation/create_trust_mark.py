#!/usr/bin/env python3
import argparse

from fedservice.utils import make_federation_combo
from idpyoidc.util import load_config_file

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dir_name')
    parser.add_argument('-e', '--entity_id')
    parser.add_argument('-m', '--trust_mark_type')
    args = parser.parse_args()

    cnf = load_config_file(f"{args.dir_name}/conf.json")
    server = make_federation_combo(**cnf["entity"])

    _tme = server.server.trust_mark_entity
    _trust_mark = _tme.create_trust_mark(args.trust_mark_type, args.entity_id)
    print(_trust_mark)
