import os
import sys

from cryptojwt.utils import importer
from idpyoidc.server.util import execute

from fedservice.entity import FederationEntity

BASEDIR = os.path.abspath(os.path.dirname(__file__))
sys.path.append(BASEDIR)
import entities.entity

def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


FEDERATION = {
    "https://ta.example.org": {
        "federation_entity": {
            "subordinates": ["https://rp.example.org"],
            "preference": {
                "organization_name": "The example federation operator",
                "organization_uri": "https://ta.example.com",
                "contacts": "operations@ta.example.com"
            },
        }
    },
    "https://rp.example.org": {
        "federation_entity": {
            "trust_anchors": ["https://ta.example.org"],
            "authority_hints": ["https://ta.example.org"]
        },
        "openid_relying_party": {}
    }
}


def execute_function(function, **kwargs):
    if isinstance(function, str):
        return importer(function)(**kwargs)
    else:
        return function(**kwargs)


def make_entity(**kwargs):
    function = entities.entity.main
    entity = execute_function(function, **kwargs)
    return entity


def get_subordinate_info(entity):
    if isinstance(entity, FederationEntity):
        fed_ent = entity
        entity_types = ["federation_entity"]
    else:
        fed_ent = entity["federation_entity"]
        entity_types = list(entity.keys())

    jwks = fed_ent.context.keyjar.export_jwks()
    return {"jwks": jwks, "entity_types": entity_types, "authority_hints": fed_ent.context.authority_hints}


def get_trust_anchor_info(entity):
    if isinstance(entity, FederationEntity):
        fed_ent = entity
    else:
        fed_ent = entity["federation_entity"]

    jwks = fed_ent.context.keyjar.export_jwks()
    return {"jwks": jwks}


def build_federation(federation_conf):
    entity = {}
    for entity_id, specification in federation_conf.items():
        entity[entity_id] = make_entity(entity_id=entity_id, **specification)

    # add subordinates
    for entity_id, ent in entity.items():
        if isinstance(ent, FederationEntity):
            fed_ent = ent
        else:
            fed_ent = ent["federation_entity"]

        subordinates = federation_conf[entity_id]['federation_entity'].get("subordinates", None)
        if subordinates:
            if isinstance(subordinates, list):
                for sub in subordinates:
                    fed_ent.server.subordinate[sub] = get_subordinate_info(entity[sub])
            else:
                fed_ent.server.subordinate = execute(subordinates)

        trust_anchor = federation_conf[entity_id]['federation_entity'].get("trust_anchors", None)
        if trust_anchor:
            for ta_entity_id in trust_anchor:
                _info = get_trust_anchor_info(entity[ta_entity_id])
                fed_ent.add_trust_anchor(ta_entity_id, _info["jwks"])

    return entity


if __name__ == '__main__':
    entity = build_federation(FEDERATION)
