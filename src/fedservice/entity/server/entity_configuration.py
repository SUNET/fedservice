from typing import Callable
from typing import Optional
from typing import Union

from idpyoidc.message import Message
from idpyoidc.message import oauth2
from idpyoidc.server import Endpoint

from fedservice import message
from fedservice.entity.utils import get_federation_entity
from fedservice.entity_statement.create import create_entity_configuration


class EntityConfiguration(Endpoint):
    request_cls = oauth2.Message
    response_cls = message.EntityConfiguration
    request_format = ""
    response_format = "jose"
    response_placement = "body"
    response_content_type = "application/entity-statement+jwt; charset=utf-8"
    name = "entity_configuration"
    endpoint_name = ""
    default_capabilities = None
    provider_info_attributes = None
    auth_method_attribute = ""

    def __init__(self, upstream_get, **kwargs):
        Endpoint.__init__(self, upstream_get=upstream_get, **kwargs)

    def process_request(self, request=None, **kwargs):
        _server = self.upstream_get("unit")
        _fed_entity = get_federation_entity(self)
        _entity_id = _fed_entity.get_attribute('entity_id')

        if _fed_entity.upstream_get:
            _metadata = _fed_entity.upstream_get("metadata")
        else:
            _metadata = _fed_entity.get_metadata()

        if _fed_entity.context.trust_marks:
            if isinstance(_fed_entity.context.trust_marks, Callable):
                args = {"trust_marks": _fed_entity.context.get_trust_marks()}
            else:
                args = {"trust_marks": _fed_entity.context.trust_marks}
        else:
            args = {}

        _trust_mark_issuers = _fed_entity.context.trust_mark_issuers
        if _trust_mark_issuers:
            # Ensure trust_mark_issuers is JSON-serializable by wrapping in dict()
            args["trust_mark_issuers"] = dict(_trust_mark_issuers)

        _trust_mark_owners = _fed_entity.context.trust_mark_owners
        if _trust_mark_owners:
            args["trust_mark_owners"] = dict(_trust_mark_owners)

        _ec = create_entity_configuration(iss=_entity_id,
                                          key_jar=_fed_entity.get_attribute('keyjar'),
                                          metadata=_metadata,
                                          authority_hints=_server.upstream_get('authority_hints'),
                                          **args
                                          )
        return {"response": _ec}

    def response_info(
            self,
            response_args: Optional[dict] = None,
            request: Optional[Union[Message, dict]] = None,
            error: Optional[str] = "",
            **kwargs
    ) -> dict:
        if "response" in kwargs:
            return kwargs["response"]
