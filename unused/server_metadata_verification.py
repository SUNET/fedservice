import json
import logging
from typing import Optional
from typing import Union

from cryptojwt import JWS
from cryptojwt.jws.utils import alg2keytype
from idpyoidc.message import Message
from idpyoidc.message import oidc
from idpyoidc.server.endpoint import Endpoint

from fedservice.entity.function import apply_policies
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import verify_trust_chains
from fedservice.entity.function.trust_chain_collector import verify_self_signed_signature
from fedservice.entity.utils import get_federation_entity

logger = logging.getLogger(__name__)


class MetadataVerification(Endpoint):
    request_cls = oidc.Message
    response_format = "text"
    content_type = "text/html"
    name = "metadata_verification"
    endpoint_name = 'federation_metadata_verification_endpoint'

    def __init__(self, upstream_get, **kwargs):
        Endpoint.__init__(self, upstream_get, **kwargs)
        self.response_type = kwargs.get("response_type", "204")
        self.signing_algorithm = kwargs.get("signing_algorithm", "RS256")

    def process_request(self, request=None, **kwargs):
        _federation_entity = get_federation_entity(self)
        payload = verify_self_signed_signature(request['registration_response'])
        # Do I trust the TA the OP chose ?
        _trust_anchor = payload['trust_anchor']
        logger.debug(f"trust_anchor_id: {_trust_anchor}")
        if _trust_anchor not in _federation_entity.function.trust_chain_collector.trust_anchors:
            raise ValueError("Trust anchor I don't trust")

        # Verify that I can collect a trust chain from the subject to a trust anchor
        _chains, _ = collect_trust_chains(self.upstream_get('unit'),
                                          entity_id=payload['sub'],
                                          stop_at=_trust_anchor)
        _trust_chains = verify_trust_chains(_federation_entity, _chains,
                                            request['registration_response'])
        # should only be one chain
        if _trust_chains == []:
            raise SystemError(
                f"Could not verify any trust chain ending in {_trust_anchor}")
        if len(_trust_chains) != 1:
            raise SystemError(f"More then one chain ending in {_trust_anchor}")

        _trust_chains[0].verified_chain[-1]['metadata'] = payload['metadata']
        _trust_chains = apply_policies(_federation_entity, _trust_chains)

        # If applying the policies doesn't change anything then everything is as it should be
        if _trust_chains[0].metadata == payload['metadata']:
            # Two variants, either 200 with signed metadata
            # or 204 with no message
            if self.response_type == "200":
                _keyjar = self.upstream_get("attibute", "keyjar")
                _jws = JWS(json.dumps(_trust_chains[0].metadata))
                _key_type = alg2keytype(self.signing_algorithm)
                _signed_jwt = _jws.sign_compact(_keyjar.get_signing_keys(key_type=_key_type))
                return {"response_msg": _signed_jwt}
            else:
                return {"response_msg": "OK"}
        else:
            return {
                "error": "invalid_request",
                "error_description": "Could not verify the metadata"
            }

    def response_info(
            self,
            response_args: Optional[dict] = None,
            request: Optional[Union[Message, dict]] = None,
            **kwargs
    ) -> dict:
        return response_args
