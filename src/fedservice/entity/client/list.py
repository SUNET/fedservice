from typing import Callable
from typing import Optional
from typing import Union
from urllib.parse import urlencode

from idpyoidc.client.configure import Configuration
from idpyoidc.message.oauth2 import ResponseMessage

from fedservice.entity.function.trust_anchor import get_verified_endpoint
from fedservice.entity.service import FederationService


class List(FederationService):
    """The service that talks to the OIDC federation List endpoint."""

    response_cls = list
    error_msg = ResponseMessage
    synchronous = True
    service_name = "list"
    http_method = "GET"
    endpoint_name = "federation_list_endpoint"
    response_body_type = "json"

    def __init__(self,
                 upstream_get: Callable,
                 conf: Optional[Union[dict, Configuration]] = None):
        FederationService.__init__(self, upstream_get, conf=conf)

    def get_request_parameters(
            self,
            request_args: Optional[dict] = None,
            authn_method: Optional[str] = "",
            endpoint: Optional[str] = "",
            entity_id: Optional[str] = "",
            **kwargs
    ) -> Union[dict, None]:
        """
        Builds the request message and constructs the HTTP headers.

        :param request_args: Message arguments
        :param authn_method: Client authentication method
        :param endpoint:
        :param kwargs: extra keyword arguments
        :return: List of entity IDs
        """
        if not endpoint:
            endpoint = get_verified_endpoint(self, entity_id, self.endpoint_name)

        qpart = {}
        for arg in ["entity_type", "trust_marked", "trust_mark_type", "intermediate"]:
            val = kwargs.get(arg)
            if val:
                qpart[arg] = val

        if qpart:
            return {"url": f"{endpoint}?{urlencode(qpart)}", 'method': self.http_method}
        else:
            return {"url": f"{endpoint}", 'method': self.http_method}
