import json
import logging
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import JWT
from idpyoidc.message import Message
from idpyoidc.message import oidc
from idpyoidc.server.endpoint import Endpoint

logger = logging.getLogger(__name__)


def create_trust_mark(keyjar, entity_id, **kwargs):
    packer = JWT(key_jar=keyjar, iss=entity_id)
    return packer.pack(payload=kwargs)


class TrustMarkList(Endpoint):
    request_cls = oidc.Message
    response_format = "json"
    name = "trust_mark_list"
    endpoint_name = 'federation_trust_mark_list_endpoint'

    def __init__(self,
                 upstream_get: Callable,
                 **kwargs):
        _client_authn_method = kwargs.get("client_authn_method", None)
        if not _client_authn_method:
            kwargs["client_authn_method"] = ["none"]

        Endpoint.__init__(self, upstream_get, **kwargs)

    def process_request(self,
                        request: Optional[dict] = None,
                        **kwargs) -> dict:
        _trust_mark_entity = self.upstream_get("unit")

        if 'sub' in request and 'trust_mark_type' in request:
            if _trust_mark_entity.find(request['trust_mark_type'], request['sub']):
                return {"response_msg": json.dumps([request["sub"]])}
        elif 'trust_mark_type' in request:
            _lst = _trust_mark_entity.list(request["trust_mark_type"])
            if _lst:
                return {"response_msg": json.dumps(_lst)}

        return {"response_msg": []}

    def response_info(
            self,
            response_args: Optional[dict] = None,
            request: Optional[Union[Message, dict]] = None,
            **kwargs
    ) -> dict:
        return response_args
