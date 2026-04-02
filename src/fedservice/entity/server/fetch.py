import logging

from idpyoidc.message import oidc
from idpyoidc.server.endpoint import Endpoint

from fedservice import message
from fedservice.entity_statement.create import create_subordinate_statement
from fedservice.exception import UnknownEntity

logger = logging.getLogger(__name__)


class Fetch(Endpoint):
    request_cls = oidc.Message
    response_cls = message.SubordinateStatement
    response_format = "jose"
    response_content_type = "application/entity-statement+jwt"
    name = "fetch"
    endpoint_name = "federation_fetch_endpoint"

    def __init__(self, upstream_get, **kwargs):
        Endpoint.__init__(self, upstream_get=upstream_get, **kwargs)

    def get_policy(self, entity_id):
        pass

    def process_request(self, request=None, **kwargs):
        _context = self.upstream_get("context")
        _issuer = request.get("iss")
        if not _issuer:
            _issuer = self.upstream_get('attribute', 'entity_id')

        _sub = request.get("sub")
        _keyjar = self.upstream_get('attribute', 'keyjar')
        # if not _sub or _sub == _issuer:
        #     _server = self.upstream_get("server")
        #     _entity = _server.upstream_get('unit')
        #     _metadata = _entity.get_metadata()
        #     _es = create_entity_configuration(iss=_entity.context.entity_id,
        #                                       sub=_entity.context.entity_id,
        #                                       key_jar=_keyjar,
        #                                       metadata=_metadata,
        #                                       authority_hints=self.upstream_get('authority_hints'))
        # else:
        _server = self.upstream_get("unit")
        # Information stored about this entity. Contains jwks and possibly entity type and authority_hints
        _response = _server.subordinate.get(_sub)
        if not _response:
            logger.debug(f"Unknown subordinate: {_sub}")
            logger.debug(f"Known subordinates: {list(_server.subordinate.keys())}")
            raise UnknownEntity(_sub)

        _policy = _server.policy.get(_sub)
        if not _policy:  # No entity specific policy
            if 'entity_types' in _response:
                _entity_types = _response['entity_types']
                _response = {k: v for k, v in _response.items() if k != 'entity_types'}
                _policy = {'metadata': {}, 'metadata_policy': {}}
                for entity_type in _entity_types:
                    _et_policy = _server.policy.get(entity_type)
                    if not _et_policy:
                        continue
                    for _typ in ['metadata', 'metadata_policy']:
                        if _typ in _et_policy:
                            try:
                                _policy[_typ].update({entity_type: _et_policy[_typ]})
                            except KeyError:
                                _policy[_typ] = {entity_type: _et_policy[_typ]}

                if _policy == {'metadata': {}, 'metadata_policy': {}}:  # Nothing has changed
                    _policy = None

        if _policy:
            _response.update(_policy)

        _es = create_subordinate_statement(iss=_issuer,
                                           sub=_sub,
                                           key_jar=_keyjar,
                                           **_response)
        return {"response_msg": _es}
