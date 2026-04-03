import json
import logging
from typing import Optional
from typing import Union

from idpyoidc.message import Message
from idpyoidc.server.endpoint import Endpoint

from fedservice.entity.utils import get_federation_entity
from fedservice.exception import NoTrustedClaims
from fedservice.message import WhoRequest

logger = logging.getLogger(__name__)


class Who(Endpoint):
    request_cls = WhoRequest
    response_format = "json"
    content_type = 'application/json'
    name = "who"
    endpoint_name = 'sunet_who_endpoint'

    def __init__(self, upstream_get, **kwargs):
        Endpoint.__init__(self, upstream_get, **kwargs)
        self.entity_type = kwargs.get("entity_type", "credential_issuer")
        if self.entity_type == "credential_issuer":
            self.credential_type = kwargs.get("credential_type", "PersonIdentificationData")
            self.trust_mark_type = kwargs.get("trust_mark_type",
                                            "http://dc4eu.example.com/PersonIdentificationData/se")
        else:
            self.credential_type = ""
            self.trust_mark_type = kwargs.get("trust_mark_type", "")

    def process_request(self, request=None, trust_anchor: str = "" ,**kwargs):
        if not request:
            request = {}

        _federation_entity = get_federation_entity(self)
        # _trust_anchor = request['anchor']

        _entity_type = request.get("entity_type", self.entity_type)
        servers = []

        # Am I the TA or not
        if trust_anchor and trust_anchor == self.upstream_get("attribute", "entity_id"):
            # list my subordinates
            list_resp = _federation_entity.do_request(
                'list', entity_id=self.upstream_get("attribute", "entity_id"))
        elif trust_anchor:
            # ask the TA for it's subordinates
            # Check that it's a TA I trust
            if trust_anchor not in list(_federation_entity.trust_anchors.keys()):
                raise NoTrustedClaims("Got a Trust anchor I don't trust")

            list_resp = _federation_entity.do_request('list', entity_id=trust_anchor)
        else: #
            raise AttributeError("Missing trust anchor specification")

        # print(f"Subordinates to TA: {list_resp}")
        for entity_id in list_resp:
            servers.extend(
                _federation_entity.trawl(_federation_entity.entity_id, entity_id,
                                         entity_type=_entity_type))

        _srv = {}
        credential_type = request.get("credential_type", self.credential_type)
        if credential_type:
            for eid in set(servers):
                _metadata = _federation_entity.get_verified_metadata(eid)
                # logger.info(json.dumps(oci_metadata, sort_keys=True, indent=4))
                for cs in _metadata['openid_credential_issuer']["credentials_supported"]:
                    if credential_type in cs["credential_definition"]["type"]:
                        _srv[eid] = _metadata
                        break

        tm_id = request.get("trust_mark_type", self.trust_mark_type)
        if tm_id:
            server_to_use = []
            for eid, metadata in _srv.items():
                _trust_chains = _federation_entity.get_trust_chains(eid)
                if not _trust_chains:
                    return "Couldn't collect Trust Chains", 400
                else:
                    _trust_chain = _trust_chains[0]

                _ec = _trust_chain.verified_chain[-1]
                if "trust_marks" in _ec:
                    for _mark in _ec["trust_marks"]:
                        _verified_trust_mark = _federation_entity.verify_trust_mark(
                            _mark, check_with_issuer=True)
                        if _verified_trust_mark.get("trust_mark_type") == tm_id:
                            server_to_use.append(eid)
        else:
            server_to_use = list(_srv.keys())

        return {'response_args': {"entities_to_use": server_to_use}}

    def response_info(
            self,
            response_args: Optional[dict] = None,
            request: Optional[Union[Message, dict]] = None,
            **kwargs
    ) -> dict:
        return response_args
