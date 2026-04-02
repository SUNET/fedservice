#! /usr/bin/env python3
import json
import sys

import requests
from cryptojwt import KeyJar
from cryptojwt.jws.jws import factory
from idpyoidc.key_import import import_jwks
from idpyoidc.server.exception import ServiceError

from fedservice.message import EntityConfiguration


def get_self_signed_entity_statement(entity_id):
    _url = entity_id + "/.well-known/openid-federation"
    _response = requests.request("GET", _url, verify=False)
    if _response.status_code != 200:
        raise ServiceError(_response.reason)
    _jws = factory(_response.text)
    _payload = _jws.jwt.payload()
    entity_statement = EntityConfiguration(**_payload)
    _key_jar = KeyJar()
    # verify  entity_statement["iss"]
    _key_jar = import_jwks(_key_jar, entity_statement['jwks'], entity_id)
    _keys = _key_jar.get_jwt_verify_keys(_jws.jwt)
    _res = _jws.verify_compact(keys=_keys)
    return _res


def list_entities(list_endpoint):
    _response = requests.request("GET", list_endpoint, verify=False)
    _list = json.loads(_response.text)
    return _list


def fetch_entity(fetch_endpoint, iss, sub, iss_entity_statement):
    _response = requests.request("GET", fetch_endpoint, verify=False,
                                 params={'iss': iss, 'sub': sub})
    _jws = factory(_response.text)
    _key_jar = KeyJar()
    _key_jar.import_jwks(iss_entity_statement['jwks'], iss)
    _keys = _key_jar.get_jwt_verify_keys(_jws.jwt)
    _res = _jws.verify_compact(keys=_keys)
    return _res


def print_entity_statement(entity_id, entity_statement, typ):
    print(30 * "_" + f" entity_{typ} for {entity_id} " + 30 * "_")
    print()
    print(json.dumps(entity_statement, indent=2, sort_keys=True))
    print()


if __name__ == "__main__":
    entity_id = sys.argv[1]
    _entity_statement = get_self_signed_entity_statement(entity_id)
    assert _entity_statement["iss"] == entity_id
    print_entity_statement(entity_id, _entity_statement, "configuration")
    endpoint = {}
    # Can be one of federation_entity, openid_relying_party, openid_provider, ..
    _ent_metadata = _entity_statement["metadata"].get("federation_entity")
    if _ent_metadata:
        for endp in ["list", "fetch", "resolve"]:
            _url = _ent_metadata.get(f"federation_{endp}_endpoint")
            if _url:
                endpoint[endp] = _url

    print(30 * '=' + "list" + 30 * "=")
    if "list" in endpoint and "fetch" in endpoint:
        _list = list_entities(endpoint["list"])
        for _entity in _list:
            _statement = fetch_entity(endpoint["fetch"], entity_id, _entity, _entity_statement)
            print_entity_statement(_entity, _statement, "statement")
