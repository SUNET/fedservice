import logging
from typing import Callable
from typing import Optional
from typing import Union
from urllib.parse import urlparse

import requests
from idpyoidc.client.configure import Configuration
from idpyoidc.message import oauth2
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.node import topmost_unit

from fedservice.entity import FederationEntity
from fedservice.entity.service import FederationService
from fedservice.entity.utils import get_federation_entity
from fedservice.message import EntityConfiguration as MSG_EntityConfiguration

logger = logging.getLogger(__name__)

WELL_KNOWN_PATTERN = "{}/.well-known/openid-federation"


def construct_well_known_url(entity_id, typ):
    p = urlparse(entity_id)
    return f'{p.scheme}://{p.netloc}/.well-known/{typ}'


def construct_tenant_well_known_url(entity_id, typ):
    p = urlparse(entity_id)
    return f'{p.scheme}://{p.netloc}{p.path}/.well-known/{typ}'


class EntityConfiguration(FederationService):
    msg_type = oauth2.Message
    response_cls = MSG_EntityConfiguration
    error_msg = ResponseMessage
    synchronous = True
    service_name = "entity_configuration"
    http_method = "GET"
    response_body_type = "jwt"
    response_content_type = "application/entity-statement+jwt"

    def __init__(self,
                 upstream_get: Callable,
                 conf: Optional[Union[dict, Configuration]] = None):
        """The service that talks to the OIDC federation well-known endpoint."""
        FederationService.__init__(self, upstream_get, conf=conf)
        self.httpc = requests.request
        self.httpc_params = {}

    def get_request_parameters(
            self, request_args=None, method="", request_body_type="", authn_method="",
            tenant: Optional[bool] = False, **kwargs
    ) -> dict:
        """
        Builds the request message and constructs the HTTP headers.

        This is the starting point for a pipeline that will:

        - construct the request message
        - add/remove information to/from the request message in the way a
            specific client authentication method requires.
        - gather a set of HTTP headers like Content-type and Authorization.
        - serialize the request message into the necessary format (JSON,
            urlencoded, signed JWT)

        :param request_body_type: Which serialization to use for the HTTP body
        :param method: HTTP method used.
        :param authn_method: Client authentication method
        :param request_args: Message arguments
        :param kwargs: extra keyword arguments
        :return: Dictionary with the necessary information for the HTTP
            request
        """
        if not method:
            method = self.http_method

        if request_args:
            _issuer = request_args.get('entity_id', request_args.get("iss", ""))
        else:
            _issuer = kwargs.get("entity_id", kwargs.get("iss", ""))

        if not _issuer:
            _root = topmost_unit(self)
            if isinstance(_root, FederationEntity):
                _issuer = _root.entity_id
            else:
                for key, _unit in _root.items():
                    if key == "federation_entity":
                        pass
                    else:
                        _context = getattr(_unit, "context", None)
                        if _context:
                            _issuer = _unit.context.get("issuer", None)
                            if _issuer:
                                break

            if not _issuer:
                raise AttributeError("Missing issuer id")

        if tenant:
            _url = construct_tenant_well_known_url(_issuer, "openid-federation")
        else:
            _url = construct_well_known_url(_issuer, "openid-federation")

        _info = {
            "method": method,
            "url": _url
        }

        return _info

    def post_parse_response(self, response, **kwargs):
        root = get_federation_entity(self)
        _collector = root.function.trust_chain_collector
        _collector.config_cache[response["iss"]] = response

        return response
