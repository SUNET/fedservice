from typing import Callable
from typing import Optional
from typing import Union
from urllib.parse import urlencode

from cryptojwt.jws.jws import factory
from idpyoidc.client.configure import Configuration
from idpyoidc.exception import MissingAttribute
from idpyoidc.message import oauth2
from idpyoidc.message.oauth2 import ResponseMessage

from fedservice import message
from fedservice.entity.service import FederationService


class TrustMarkStatus(FederationService):
    """The service that talks to the OIDC federation Status endpoint."""

    msg_type = oauth2.Message
    response_cls = message.Message
    error_msg = ResponseMessage
    synchronous = True
    service_name = "trust_mark_status"
    http_method = "GET"

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
            **kwargs
    ) -> dict:
        """
        Builds the request message and constructs the HTTP headers.

        :param method: HTTP method used.
        :param authn_method: Client authentication method
        :param request_args: Message arguments
        :param request_body_type:
        :param fetch_endpoint:
        :param kwargs: extra keyword arguments
        :return: Dictionary with the necessary information for the HTTP request
        """
        if not method:
            method = self.http_method

        if "trust_mark" in request_args:
            _q_args = {'trust_mark': request_args["trust_mark"]}
            _jws = factory(request_args["trust_mark"])
            tm_payload = _jws.jwt.payload()
            fetch_endpoint = tm_payload['iss']
        else:
            _q_args = {k: v for k, v in request_args.items() if k in ['sub', 'trust_mark_type', 'iat']}
            if not fetch_endpoint:
                fetch_endpoint = kwargs.get("endpoint")
                if not fetch_endpoint:
                    raise MissingAttribute('fetch_endpoint')

        _url = f"{fetch_endpoint}?{urlencode(_q_args)}"

        return {"url": _url, 'method': method}
