from typing import Callable
from typing import Optional
from typing import Union

from fedservice import get_payload

from fedservice.entity.function import verify_trust_chain
from idpyoidc.client.configure import Configuration
from idpyoidc.message.oauth2 import ResponseMessage

from fedservice import message
from fedservice.entity.service import FederationService
from fedservice.message import ResolveRequest


class Resolve(FederationService):
    """The service that talks to the OIDC federation List endpoint."""

    response_cls = message.ResolveResponse
    error_msg = ResponseMessage
    synchronous = True
    service_name = "resolve"
    http_method = "GET"
    response_body_type = "jose"
    payload_type = 'resolve-response+jwt'

    def __init__(self,
                 upstream_get: Callable,
                 conf: Optional[Union[dict, Configuration]] = None):
        FederationService.__init__(self, upstream_get, conf=conf)

    def get_request_parameters(
            self,
            request_args: Optional[dict] = None,
            authn_method: Optional[str] = "",
            endpoint: Optional[str] = "",
            **kwargs
    ) -> dict:
        """
        Builds the request message and constructs the HTTP headers.

        :param request_args: Message arguments
        :param authn_method: Client authentication method
        :param endpoint:
        :param kwargs: extra keyword arguments
        :return: List of entity IDs
        """
        if not endpoint:
            self.upstream_get('unit')
            raise AttributeError("Missing endpoint")

        _req = ResolveRequest(**request_args)
        _req.verify()

        return {"url": _req.request(endpoint), 'method': self.http_method}

    def post_parse_response(self, context, response, **kwargs):
        """
        Will verify the trust chain and calculate an expiration date for the whole response

        :param response:
        :param kwargs:
        :return:
        """

        trust_chains = verify_trust_chain(self, response["trust_chain"])
        trust_chain = trust_chains[0]

        exp = trust_chain.exp

        tms = response.get("trust_marks")
        if tms:
            for tm in tms:
                payload = get_payload(tm['trust_mark'])
                _exp = payload.get('exp')
                if _exp:
                    if _exp < exp:
                        exp = _exp

        trust_chain.exp = exp

        response['verified_trust_chain'] = trust_chain
        response["exp"] = exp
        return response
