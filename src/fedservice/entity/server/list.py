import json
import logging

from cryptojwt import JWT
from cryptojwt import KeyJar
from idpyoidc.key_import import import_jwks
from idpyoidc.message import oidc
from idpyoidc.server.endpoint import Endpoint

logger = logging.getLogger(__name__)


class List(Endpoint):
    request_cls = oidc.Message
    # response_cls = EntityIDList
    response_format = 'json'
    name = "list"
    endpoint_name = 'federation_list_endpoint'

    def __init__(self, upstream_get, extended=False, **kwargs):
        Endpoint.__init__(self, upstream_get, **kwargs)
        self.extended = extended

    def filter(self,
               subordinates: dict,
               entity_type: str = '',
               trust_mark_id: str = '',
               trust_marked=None,
               **kwargs):
        match = []
        for entity_id, conf in subordinates.items():
            matched = False
            if entity_type:
                if entity_type in conf['metadata']:
                    matched = True
            if trust_marked:
                if 'trust_marks' in conf:
                    matched = True
                else:
                    matched = False
            if trust_mark_id:
                trust_marks = conf.get('trust_marks')
                matched = False
                for trust_mark in trust_marks:
                    if trust_mark['trust_mark_id'] == trust_mark_id:
                        matched = True

            if matched:
                match.append(entity_id)
        return match

    def process_request(self, request=None, **kwargs):
        _db = self.upstream_get("unit").subordinate
        if not request or set(request.keys()).issubset({"client_id", "authenticated"}):
            return {'response_msg': json.dumps(list(_db.keys()))}
        else:
            matched_entity_ids = set()
            subordinate_conf = None
            # I know about entity_types and intermediate or not from the registration
            for entity_id, item in _db.items():
                if "intermediate" in request and request["intermediate"]:
                    if "intermediate" in item and item["intermediate"]:
                        matched_entity_ids.add(entity_id)
                        continue
                if "entity_type" in request:
                    if request["entity_type"] in item["entity_type"]:
                        matched_entity_ids.add(entity_id)

            # I don't expect to know about trust marks from the registration
            if "trust_marked" in request or "trust_mark_id" in request:
                subordinate_conf = self.collect_subordinates()
                matched_entity_ids.update(self.filter(subordinates=subordinate_conf, **request))

            if self.extended and subordinate_conf:
                return {"response_msg": json.dumps({id: subordinate_conf[id] for id in
                                                    matched_entity_ids})}
            else:
                return {"response_msg": json.dumps(list(matched_entity_ids))}

    def collect_subordinates(self) -> dict:
        _server_entity = self.upstream_get("unit")
        _federation_entity = _server_entity.upstream_get("unit")
        keyjar = KeyJar()
        _collector = _federation_entity.function.trust_chain_collector
        sub = {}
        for entity_id, conf in _federation_entity.server.subordinate.items():
            #  get entity configuration for subordinate
            _entity_configuration = _collector.get_entity_configuration(entity_id)
            # Verify signature with the keys I have
            keyjar = import_jwks(keyjar, conf['jwks'], entity_id)
            _jwt = JWT(key_jar=keyjar)
            _ec = _jwt.unpack(_entity_configuration)
            sub[entity_id] = _ec
        return sub
