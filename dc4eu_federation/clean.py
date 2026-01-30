#!/usr/bin/env python3
import os
import sys

# federation types
DIRECTORIES = {
    "dc4eu": ["trust_anchor", "trust_mark_issuer", "wallet_provider"],
    "identity": ["trust_anchor", "trust_mark_issuer", "openid_provider", "relying_party_explicit"]
}

PERS_DIRECTORIES = ["subordinate", "trust_mark_issuers", "trust_anchors"]
def rm_persistence(directory):
    for _file in os.listdir(directory):
        _full_name = os.path.join(directory, _file)
        if os.path.isfile(_full_name):
            os.unlink(_full_name)


for directory in DIRECTORIES[sys.argv[1]]:
    for _file in os.listdir(directory):
        _full_name = os.path.join(directory, _file)
        if os.path.isfile(_full_name):
            if _file in ["conf.json", "views.py"]:
                pass
            else:
                os.unlink(_full_name)
        elif os.path.isdir(_full_name) and _file in PERS_DIRECTORIES:
            rm_persistence(_full_name)
