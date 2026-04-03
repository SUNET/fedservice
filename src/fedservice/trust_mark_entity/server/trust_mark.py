import logging
from typing import Callable
from typing import List
from typing import Optional
from typing import Union

from cryptojwt import JWT
from idpyoidc.message import Message
from idpyoidc.message import oidc
from idpyoidc.server.endpoint import Endpoint

from fedservice.message import TrustMarkRequest

logger = logging.getLogger(__name__)


def create_trust_mark(keyjar, entity_id, **kwargs):
    packer = JWT(key_jar=keyjar, iss=entity_id)
    return packer.pack(payload=kwargs)


class TrustMark(Endpoint):
    request_cls = TrustMarkRequest
    name = "trust_mark"
    endpoint_name = 'federation_trust_mark_endpoint'
    response_format = "jose"
    response_content_type = "application/trust_mark+jwt; charset=utf-8"

    def __init__(self,
                 upstream_get: Callable,
                 auth_signing_alg_values: Optional[List[str]] = None,
                 **kwargs):
        _client_authn_method = kwargs.get("client_authn_method", None)
        if not _client_authn_method:
            kwargs["client_authn_method"] = ["none"]
        Endpoint.__init__(self, upstream_get, **kwargs)
        self.auth_signing_alg_values = auth_signing_alg_values or []

    def process_request(self,
                        request: Optional[dict] = None,
                        **kwargs) -> dict:

        _trust_mark_issuer = self.upstream_get("unit")

        _id = request.get("trust_mark_type")
        _sub = request.get("sub")  # Required parameter

        _jws = _trust_mark_issuer.create_trust_mark(_id, _sub)

        return {"response": _jws}

    def response_info(
            self,
            response_args: Optional[dict] = None,
            request: Optional[Union[Message, dict]] = None,
            error: Optional[str] = "",
            **kwargs
    ) -> dict:
        if "http_response" in response_args:
            return response_args["response"]
        if "response" in response_args:
            return response_args["response"]
