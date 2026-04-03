from typing import Callable
from typing import Optional
from typing import Union

from fedservice.entity.function import get_verified_trust_chains

from fedservice.entity.utils import get_federation_entity
from idpyoidc.client.configure import Configuration
from idpyoidc.exception import MissingAttribute
from idpyoidc.message import Message
from idpyoidc.message import oauth2
from idpyoidc.message.oauth2 import ResponseMessage

from fedservice import message
from fedservice.entity.service import FederationService
from fedservice.message import TrustMarkRequest


class TrustMark(FederationService):
    """The service that talks to the Trust Mark endpoint."""

    msg_type = oauth2.Message
    response_cls = message.Message
    error_msg = ResponseMessage
    synchronous = True
    service_name = "trust_mark"
    http_method = "GET"
    response_body_type = "application/trust_mark+jwt"

    def __init__(self,
                 upstream_get: Callable,
                 conf: Optional[Union[dict, Configuration]] = None):
        FederationService.__init__(self, upstream_get, conf=conf)

    def get_headers_args(self):
        # audience = _server_endpoint.full_path,
        # algorithm = "ES256",

        return {"client_id": self.upstream_get("context").entity_id}

    def construct_request(
            self,
            request_args: Optional[dict] = None,
            **kwargs
    ) -> Message:
        """
        Builds the request message and constructs the HTTP headers.

        :param request_args: Message arguments
        :param kwargs: extra keyword arguments
        :return: Dictionary with the necessary information for the HTTP request
        """

        if "trust_mark_type" not in request_args:
            raise MissingAttribute("Need a trust mark type")

        return TrustMarkRequest(**request_args)

    def get_endpoint(self):
        federation_entity = get_federation_entity(self)
        trust_chains=federation_entity.get_trust_chains(federation_entity.client.context.issuer)
        if trust_chains:
            pass
        else:
            trust_chains = get_verified_trust_chains(federation_entity, federation_entity.client.context.issuer)
            if trust_chains:
                federation_entity.store_trust_chains(federation_entity.client.context.issuer, trust_chains)
            else:
                return ""

        return trust_chains[0].metadata["federation_entity"]["federation_trust_mark_endpoint"]

