#!/usr/bin/env python3
import json

from idpyoidc.util import load_config_file

from fedservice.combo import FederationCombo
from fedservice.utils import make_federation_combo
from utils import load_values_from_file

ENTITY = json.loads(open("entities.json", 'r').read())


def get_federation_entity(entity):
    if isinstance(entity, FederationCombo):
        return entity["federation_entity"]
    else:
        return entity


fed_entity = {}
for ent, info in ENTITY.items():
    _cnf = load_values_from_file(load_config_file(f"{info['dir']}/{info['config']}"))
    _ent = make_federation_combo(**_cnf["entity"])
    if isinstance(_ent, FederationCombo):
        fed_entity[ent] = _ent["federation_entity"]
    else:
        fed_entity[ent] = _ent

subordinates = {}
trust_anchor = {}

for ent, info in ENTITY.items():
    print(f"*** {ent} ***")
    if "authority_hints" in info and info["authority_hints"]:
        authorities = []
        for auth in info["authority_hints"]:
            authorities.append(fed_entity[auth].entity_id)
            if auth not in subordinates:
                subordinates[auth] = {}
            _ent_id = get_federation_entity(fed_entity[ent]).entity_id
            subordinates[auth][_ent_id] = {
                'jwks': get_federation_entity(fed_entity[ent]).keyjar.export_jwks(),
                'authority_hints': [fed_entity[auth].entity_id]
            }
        print(f"authority_hints: {authorities}")
        file_name = f"{info['dir']}/{ent}_authority_hints.json"
        with open(file_name, "w") as fp:
            fp.write(json.dumps(authorities))
    if "trust_anchors" in info and info["trust_anchors"]:
        trust_anchor[ent] = {}
        for anch in info["trust_anchors"]:
            _fed_entity = get_federation_entity(fed_entity[anch])
            _ent_id = _fed_entity.entity_id
            trust_anchor[ent][_ent_id] = _fed_entity.keyjar.export_jwks()

for auth, val in subordinates.items():
    file_name = f"{ENTITY[auth]['dir']}/{auth}_subordinates.json"
    with open(file_name, "w") as fp:
        fp.write(json.dumps(val))

    print(f"*** subordinates@{auth} ***")
    for sub, info in val.items():
        print(f"--- {sub} ---")
        print(info)

for ent, val in trust_anchor.items():
    file_name = f"{ENTITY[ent]['dir']}/{ent}_trust_anchors.json"
    with open(file_name, "w") as fp:
        fp.write(json.dumps(val))

    print(f"*** trust_anchors@{ent} ***")
    for sub, info in val.items():
        print(f"--- {sub} ---")
        print(info)
