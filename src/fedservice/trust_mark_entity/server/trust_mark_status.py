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


class TrustMarkStatus(Endpoint):
    request_cls = oidc.Message
    response_format = "json"
    name = "trust_mark_status"
    endpoint_name = 'federation_trust_mark_status_endpoint'

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
        _trust_mark_issuer = self.upstream_get("unit")

        if 'trust_mark' in request:
            _mark = _trust_mark_issuer.unpack_trust_mark(request['trust_mark'])
            if _trust_mark_issuer.find(_mark['trust_mark_id'], _mark['sub']):
                return {'response_args': {'active': True}}
        else:
            if 'sub' in request:
                _id = ""
                if 'trust_mark_id' in request:
                    _id = request['trust_mark_id']

                if _id:
                    if _trust_mark_issuer.find(_id, request['sub']):
                        return {'response_args': {'active': True}}

        return self.error_cls(error="not_found", error_description="No active trust mark matching the query")

    def response_info(
            self,
            response_args: Optional[dict] = None,
            request: Optional[Union[Message, dict]] = None,
            **kwargs
    ) -> dict:
        return response_args
