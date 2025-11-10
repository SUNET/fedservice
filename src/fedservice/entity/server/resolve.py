import logging
from typing import Optional
from typing import Union

from idpyoidc.message import Message
from idpyoidc.message import oidc
from idpyoidc.server.endpoint import Endpoint

from fedservice.entity.function import apply_policies
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import verify_trust_chains
from fedservice.entity.utils import get_federation_entity
from fedservice.entity_statement.create import create_entity_configuration

logger = logging.getLogger(__name__)


class Resolve(Endpoint):
    request_cls = oidc.Message
    response_format = "jose"
    content_type = 'application/resolve-response+jwt'
    name = "resolve"
    endpoint_name = 'federation_resolve_endpoint'

    def __init__(self, upstream_get, **kwargs):
        Endpoint.__init__(self, upstream_get, **kwargs)

    def process_request(self, request=None, **kwargs):
        _federation_entity = get_federation_entity(self)
        _trust_anchor = request['anchor']

        # verified trust chains with policy adjusted metadata
        _chains, signed_entity_configuration = collect_trust_chains(_federation_entity,
                                                                    entity_id=request['sub'],
                                                                    stop_at=_trust_anchor)
        _trust_chains = verify_trust_chains(_federation_entity, _chains,
                                            signed_entity_configuration)
        _trust_chains = apply_policies(_federation_entity, _trust_chains)

        _chosen_chain = None
        for trust_chain in _trust_chains:
            if _trust_anchor == trust_chain.anchor:
                _chosen_chain = trust_chain
                break

        if "type" in request:
            metadata = {request['type']: _chosen_chain.metadata[request['type']]}
        else:
            metadata = _chosen_chain.metadata

        # Now for the trust marks
        verified_trust_marks = []
        for _trust_mark in _chosen_chain.verified_chain[-1].get("trust_marks", []):
            _verified_mark = _federation_entity.function.trust_mark_verifier(trust_mark=_trust_mark,
                                                                             trust_anchor=_trust_anchor)
            if _verified_mark:
                verified_trust_marks.append({
                    "trust_mark_type": _verified_mark["trust_mark_type"],
                    "trust_mark": _trust_mark
                })

        trust_chain = _federation_entity.function.trust_chain_collector.get_chain(
            _chosen_chain.iss_path, _trust_anchor, kwargs.get("with_ta_ec"))

        if verified_trust_marks:
            args = {"trust_marks": verified_trust_marks}
        else:
            args = {}

        _jws = create_entity_configuration(_federation_entity.entity_id,
                                           # sub=request["sub"],
                                           key_jar=_federation_entity.get_attribute('keyjar'),
                                           metadata=metadata,
                                           trust_chain=trust_chain,
                                           **args)
        return {'response_args': _jws}

    def response_info(
            self,
            response_args: Optional[dict] = None,
            request: Optional[Union[Message, dict]] = None,
            **kwargs
    ) -> dict:
        return response_args
