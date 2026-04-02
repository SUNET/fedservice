import logging
from typing import Callable
from typing import Optional
from typing import Union
from urllib.parse import urlencode

from idpyoidc.client.configure import Configuration
from idpyoidc.message import Message
from idpyoidc.message import oauth2
from idpyoidc.message.oauth2 import ResponseMessage

from fedservice import message
from fedservice.entity.service import FederationService
from fedservice.entity.utils import get_federation_entity

logger = logging.getLogger(__name__)


def construct_entity_configuration_query(api_endpoint, issuer="", subject=""):
    if issuer:
        if subject:
            query = urlencode({"iss": issuer, "sub": subject})
        else:
            query = urlencode({"iss": issuer})

        return f"{api_endpoint}?{query}"
    else:
        return f"{api_endpoint}"


class SubordinateStatement(FederationService):
    """The service that talks to the OIDC federation Fetch endpoint."""

    msg_type = oauth2.Message
    response_cls = message.SubordinateStatement
    error_msg = ResponseMessage
    synchronous = True
    service_name = "entity_statement"
    http_method = "GET"
    endpoint_name = "federation_fetch_endpoint"
    response_body_type = "jose"
    response_content_type = "application/entity-statement+jwt"

    def __init__(self,
                 upstream_get: Callable,
                 conf: Optional[Union[dict, Configuration]] = None):
        FederationService.__init__(self, upstream_get, conf=conf)

    def get_request_parameters(
            self,
            request_args: Optional[dict] = None,
            method: Optional[str] = "",
            request_body_type: Optional[str] = "",
            authn_method: Optional[str] = "",
            fetch_endpoint: Optional[str] = "",
            issuer: Optional[str] = "",
            subject: Optional[str] = "",
            **kwargs
    ) -> dict:
        """
        Builds the request message and constructs the HTTP headers.

        :param method: HTTP method used.
        :param authn_method: Client authentication method
        :param request_args: Message arguments
        :param request_body_type:
        :param fetch_endpoint:
        :param issuer:
        :param subject:
        :param kwargs: extra keyword arguments
        :return: Dictionary with the necessary information for the HTTP request
        """
        if not method:
            method = self.http_method

        if not fetch_endpoint:
            _federation_entity = get_federation_entity(self)
            _collector = _federation_entity.function.trust_chain_collector
            if issuer in _collector.config_cache:
                _ec = _collector.config_cache[issuer]
            else:
                logger.debug(f"Entity Configuration for '{issuer}' not cached")
                _ec = _federation_entity.client.do_request("entity_configuration", entity_id=issuer)
            fetch_endpoint = _ec["metadata"]["federation_entity"][self.endpoint_name]
            if not fetch_endpoint:
                raise AttributeError("Missing endpoint")

        msg = Message()
        # sub is a MUST
        msg['sub'] = subject

        return {"url": msg.request(fetch_endpoint), 'method': method}
