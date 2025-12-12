from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt.jws.jws import factory
from idpyoidc.client.configure import Configuration
from idpyoidc.message.oauth2 import ResponseMessage

from fedservice.entity.function import get_verified_trust_chains
from fedservice.entity.service import FederationService
from fedservice.message import TrustMarkStatusRequest
from fedservice.message import TrustMarkStatusResponse


class TrustMarkStatus(FederationService):
    """The service that talks to the OIDC federation Status endpoint."""

    msg_type = TrustMarkStatusRequest
    response_cls = TrustMarkStatusResponse
    error_msg = ResponseMessage
    synchronous = True
    service_name = "trust_mark_status"
    http_method = "GET"
    payload_type = "trust-mark-status-response+jwt"

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

        _req = TrustMarkStatusRequest(**request_args)
        _req.verify()

        if not fetch_endpoint:
            fetch_endpoint = kwargs.get("endpoint")
            if not fetch_endpoint:
                _tm = factory(_req["trust_mark"])
                _trust_chains = get_verified_trust_chains(self, _tm.jwt.payload()["iss"])
                if _trust_chains:
                    fetch_endpoint = _trust_chains[0].metadata[
                        'federation_entity']['federation_trust_mark_status_endpoint']

        _url = _req.request(fetch_endpoint)

        return {"url": _url, 'method': method}
