from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import JWT
from cryptojwt.jws.jws import factory
from cryptojwt.jwt import utc_time_sans_frac

from fedservice.entity import get_federation_entity_keyjar
from fedservice.entity.function import verify_trust_chains
from idpyoidc.client.configure import Configuration
from idpyoidc.message import oauth2
from idpyoidc.message.oauth2 import ResponseMessage

from fedservice import message
from fedservice.entity.function import get_verified_trust_chains
from fedservice.entity.service import FederationService
from fedservice.entity.utils import get_federation_entity


class SignedJWKS(FederationService):
    """The service that picks up a signed JWKS."""

    msg_type = oauth2.Message
    response_cls = message.Message
    error_msg = ResponseMessage
    synchronous = True
    service_name = "signed_jwks"
    http_method = "GET"
    response_body_type = 'application/jwk-set+jwt'

    def __init__(self,
                 upstream_get: Callable,
                 conf: Optional[Union[dict, Configuration]] = None):
        FederationService.__init__(self, upstream_get, conf=conf)

    def get_endpoint(self, entity_id):
        federation_entity = get_federation_entity(self)
        # There may already be trust chains in the cache
        trust_chains = federation_entity.get_trust_chains(entity_id)
        if not trust_chains:
            trust_chains = get_verified_trust_chains(federation_entity, entity_id)
            if trust_chains:
                federation_entity.store_trust_chains(entity_id, trust_chains)
            else:
                return ""

        # list of lists with signed entity statements
        return trust_chains[0].metadata["federation_entity"]["signed_jwks_uri"]

    def get_request_parameters(self, request_args=None, **kwargs):
        return {"url": self.get_endpoint(**request_args), "method": "GET"}

    def parse_response(
            self,
            info,
            sformat: Optional[str] = "",
            state: Optional[str] = "",
            behaviour_args: Optional[dict] = None,
            **kwargs,
    ):
        _jws = factory(info)
        if _jws is None:
            raise ValueError("Not a signed JWT")
        if _jws.jwt.headers['typ'] != self.response_body_type:
            raise ValueError('Wrong JWT type')

        _verifier = JWT(key_jar=get_federation_entity_keyjar(self))
        _jwks = _verifier.unpack(info)
        return _jwks

    def update_service_context(self, resp, key="", **kwargs):
        _keyjar = get_federation_entity_keyjar(self)
        # If there are inactivated keys remove them
        _now = utc_time_sans_frac()
        _issuer = _keyjar.return_issuer(resp['iss'])
        if _issuer:
            # remove keys already marked as inactive
            _issuer.remove_outdated()
            # mark the remaining keys as inactive
            _issuer.mark_all_keys_as_inactive()

        # import the new keys
        _keyjar.import_jwks({"keys": resp["keys"]}, issuer_id=resp['iss'])
