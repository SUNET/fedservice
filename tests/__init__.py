import os

from cryptojwt.utils import importer

from fedservice.entity import FederationEntity
from fedservice.entity.utils import get_federation_entity

CRYPT_CONFIG = {
    "kwargs": {
        "keys": {
            "key_defs": [
                {"type": "OCT", "use": ["enc"], "kid": "password"},
                {"type": "OCT", "use": ["enc"], "kid": "salt"},
            ]
        },
        "iterations": 1,
    }
}

SESSION_PARAMS = {"encrypter": CRYPT_CONFIG}

RESPONSE_TYPES_SUPPORTED = [
    ["code"],
    ["id_token"],
    ["code", "id_token"],
    ["none"],
]


def create_trust_chain_messages(leaf, *entity):
    where_and_what = {}

    if isinstance(leaf, str):
        pass
    else:
        _endpoint = get_federation_entity(leaf).server.get_endpoint('entity_configuration')
        where_and_what[_endpoint.full_path] = _endpoint.process_request({})["response"]

    # now for each intermediate up to the trust anchor
    for n in range(0, len(entity)):
        ent = entity[n]
        if isinstance(ent, FederationEntity):
            _entity = ent
        else:  # A Combo
            _entity = ent['federation_entity']

        # First the entity configuration for the entity
        _endpoint = _entity.server.get_endpoint('entity_configuration')
        where_and_what[_endpoint.full_path] = _endpoint.process_request({})["response"]

        # then for the subordinate statement
        _endpoint = _entity.server.get_endpoint('fetch')
        if n == 0:
            if isinstance(leaf, str):
                _sub = leaf
            else:
                _sub = leaf.entity_id
        else:
            _sub = entity[n - 1].entity_id
        _req = _endpoint.parse_request({'iss': ent.entity_id, 'sub': _sub})
        where_and_what[_endpoint.full_path] = _endpoint.process_request(_req)["response_msg"]

    return where_and_what


def create_trust_chain(leaf, *entity):
    chain = []

    if isinstance(leaf, str):
        pass
    else:
        _endpoint = get_federation_entity(leaf).server.get_endpoint('entity_configuration')
        chain.append(_endpoint.process_request({})["response"])

    for n in range(0, len(entity)):
        ent = entity[n]
        if isinstance(ent, FederationEntity):
            _entity = ent
        else:  # A Combo
            _entity = ent['federation_entity']

        _endpoint = _entity.server.get_endpoint('entity_configuration')

        # chain.append(_endpoint.process_request({})["response"])

        _endpoint = _entity.server.get_endpoint('fetch')
        if n == 0:
            if isinstance(leaf, str):
                _sub = leaf
            else:
                _sub = leaf.entity_id
        else:
            _sub = entity[n - 1].entity_id
        _req = _endpoint.parse_request({'iss': ent.entity_id, 'sub': _sub})
        chain.append(_endpoint.process_request(_req)["response"])

    return chain

def rm_dir_files(dir):
    for file_object in os.listdir(dir):
        file_object_path = os.path.join(dir, file_object)
        if os.path.isfile(file_object_path) or os.path.islink(file_object_path):
            os.unlink(file_object_path)

