import logging
from typing import Optional

from idpyoidc.client.exception import ResponseError
from idpyoidc.client.oidc import registration
from idpyoidc.message.oidc import RegistrationRequest
from idpyoidc.message.oidc import RegistrationResponse

from fedservice.entity.function import apply_policies
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import verify_trust_chains
from fedservice.entity.function.trust_chain_collector import verify_self_signed_signature
from fedservice.entity.utils import get_federation_entity
from fedservice.exception import SignatureFailure

logger = logging.getLogger(__name__)


class Registration(registration.Registration):
    msg_type = RegistrationRequest
    response_cls = RegistrationResponse
    endpoint_name = 'federation_registration_endpoint'
    request_body_type = 'jwt'
    response_body_type = 'jwt'
    content_type = "application/entity-statement+jwt"
    name = 'registration'

    _supports = {
        "client_registration_types": ["automatic", "explicit"]
    }

    def __init__(self, upstream_get, conf=None, client_authn_factory=None, **kwargs):
        registration.Registration.__init__(self, upstream_get, conf=conf)
        #
        self.post_construct.append(self.create_entity_statement)

    # def get_provider_info_attributes(self):
    #     _pia = construct_provider_info(self.provider_info_attributes, **self.kwargs)
    #     if self.endpoint_name:
    #         _pia[self.endpoint_name] = self.full_path
    #     return _pia

    @staticmethod
    def carry_receiver(request, **kwargs):
        if 'receiver' in kwargs:
            return request, {'receiver': kwargs['receiver']}
        else:
            return request, {}

    def create_entity_statement(self, request_args: Optional[dict]= None, **kwargs):
        """
        Create a self-signed entity statement

        :param request_args:
        :param service:
        :param kwargs:
        :return:
        """

        _federation_entity = get_federation_entity(self)
        # _md = {_federation_context.entity_type: request_args.to_dict()}
        _root = _federation_entity.upstream_get('unit')
        _md = _root.get_metadata()
        _keyjar = _federation_entity.get_attribute("keyjar")

        # _entity = self.upstream_get('unit')
        # if _entity.name not in _md:
        #     _md.update(_entity.get_metadata())

        _authority_hints = _federation_entity.get_authority_hints()
        _context = _federation_entity.get_context()
        _entity_id = _federation_entity.upstream_get('attribute', 'entity_id')

        kwargs = {}
        if _context.trust_marks:
            kwargs["trust_marks"] = _context.trust_marks

        _jws = _context.create_entity_statement(
            iss=_entity_id,
            sub=_entity_id,
            metadata=_md,
            key_jar=_keyjar,
            authority_hints=_authority_hints,
            **kwargs)

        # store for later reference
        _federation_entity.entity_configuration = _jws
        return _jws

    def parse_response(self, info, sformat="", state="", **kwargs):
        resp = self.parse_federation_registration_response(info, **kwargs)
        logger.debug(f"Registration response: {resp}")
        if not resp:
            logger.error('Missing or faulty response')
            raise ResponseError("Missing or faulty response")

        return resp

    def _get_trust_anchor(self, entity_statement):
        return entity_statement.get('trust_anchor')

    def _signature_verifies(self, entity_id, trust_anchor, federation_entity):
        _chains, _ = collect_trust_chains(self.upstream_get('unit'),
                                          entity_id=entity_id,
                                          stop_at=trust_anchor)
        if not _chains:
            return False

        _trust_chains = verify_trust_chains(federation_entity, _chains)
        return True

    def parse_federation_registration_response(self, resp, **kwargs):
        """
        Receives a dynamic client registration response,

        :param resp: An entity statement as a signed JWT
        :return: A set of metadata claims
        """

        # Find the part of me that deals with the federation
        _federation_entity = get_federation_entity(self)

        payload = verify_self_signed_signature(resp)
        # Do I trust the TA the OP chose ?
        logger.debug(f"trust_anchor: {payload['trust_anchor']}")
        if payload[
            'trust_anchor'] not in _federation_entity.function.trust_chain_collector.trust_anchors:
            raise ValueError("Trust anchor I don't trust")

        # This is where I should decide to use the metadata verification service or do it
        # all myself
        # Do I have the necessary Function/Service installed
        _verifier = _federation_entity.get_function("metadata_verifier")
        if _verifier:
            #  construct the query, send it and parse the response
            _verifier_response = _verifier(resp)
            if _verifier_response:
                return _verifier_response
        else:
            # verify the signature on the response from the OP
            if not self._signature_verifies(payload["iss"], payload['trust_anchor'],
                                            _federation_entity):
                raise SignatureFailure("Could not verify signature")

            # This is the trust chain from the RP to the TA
            _chains, _ = collect_trust_chains(self.upstream_get('unit'),
                                              entity_id=self.upstream_get('attribute', 'entity_id'),
                                              stop_at=payload['trust_anchor'])
            _trust_chains = verify_trust_chains(_federation_entity, _chains, resp)
            # should only be one chain
            if len(_trust_chains) != 1:
                raise SystemError(f"More then one chain ending in {payload['trust_anchor']}")
            _metadata = payload.get("metadata")
            if _metadata:
                _trust_chains[0].verified_chain[-1]['metadata'] = _metadata
            # If it's metadata_policy what to do ?
            _trust_chains = apply_policies(_federation_entity, _trust_chains)
            _resp = _trust_chains[0].metadata['openid_relying_party']
            _context = self.upstream_get('context')
            _context.registration_response = _resp
            return _resp

    def update_service_context(self, resp, **kwargs):
        registration.Registration.update_service_context(self, resp, **kwargs)
