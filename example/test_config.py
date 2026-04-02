#!/usr/bin/env python3
import sys

from idpyoidc.util import load_config_file

from fedservice.combo import FederationCombo
from fedservice.utils import load_values_from_file
from fedservice.utils import make_federation_combo

subdir = sys.argv[1]

config_file = sys.argv[2]

_cnf = load_values_from_file(load_config_file(f"{subdir}/{config_file}"))
entity = make_federation_combo(**_cnf["entity"])
print(entity.entity_id)
if isinstance(entity, FederationCombo):
    print(entity["federation_entity"].keyjar.export_jwks())
else:
    print(entity.keyjar.export_jwks())
