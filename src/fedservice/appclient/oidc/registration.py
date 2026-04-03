import logging
from typing import Optional
from typing import Union

from cryptojwt import JWT
from idpyoidc.client.exception import ResponseError
from idpyoidc.client.oidc import registration
from idpyoidc.message import Message
from idpyoidc.message.oidc import RegistrationRequest
from idpyoidc.message.oidc import RegistrationResponse
from idpyoidc.transform import RP_URI_CLAIMS

from fedservice.appclient.oauth2.registration import create_entity_configuration as oauth2_create_entity_configuration
from fedservice.appclient.oauth2.registration import shared_update_service_context
from fedservice.entity.function import apply_policies
from fedservice.entity.function import get_verified_trust_chains
from fedservice.entity.utils import get_federation_entity
from fedservice.exception import NoTrustedChains

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

    uri_claims = RP_URI_CLAIMS

    def __init__(self, upstream_get, conf=None, client_authn_factory=None, **kwargs):
        registration.Registration.__init__(self, upstream_get, conf=conf)
        #
        self.post_construct.append(oauth2_create_entity_configuration)

    @staticmethod
    def carry_receiver(request, **kwargs):
        if 'receiver' in kwargs:
            return request, {'receiver': kwargs['receiver']}
        else:
            return request, {}

    def update_service_context(self, resp: Union[Message, dict], **kwargs):
        shared_update_service_context(service=self, resp=resp, **kwargs)

    def create_entity_configuration(self, request_args: Optional[dict] = None, **kwargs):
        """
        Create a self-signed entity statement

        :param request_args:
        :param service:
        :param kwargs:
        :return:
        """

        logger.debug(f"Create Entity Configuration")
        _federation_entity = get_federation_entity(self)
        _context = _federation_entity.get_context()
        authority_hints = _context.authority_hints
        if authority_hints:
            kwargs["authority_hints"] = authority_hints
        if "key_jar" not in kwargs:
            kwargs["key_jar"] = _federation_entity.keyjar

        _jws = _context.create_entity_configuration(iss=_federation_entity.entity_id,
                                                    **kwargs)
        return _jws

    def parse_response(self, info, sformat="", state="", **kwargs):
        resp = self.parse_federation_registration_response(info, **kwargs)
        logger.debug(f"Registration response: {resp}")
        if not resp:
            logger.error('Missing or faulty response')
            raise ResponseError("Missing or faulty response")

        return resp

    def _get_trust_anchor_id(self, entity_statement):
        return entity_statement.get('trust_anchor')

    def parse_federation_registration_response(self, resp, **kwargs):
        """
        Receives a dynamic client registration response,

        :param resp: An entity statement as a signed JWT
        :return: A set of metadata claims
        """

        # Find the part of me that deals with the federation
        _federation_entity = get_federation_entity(self)

        # verify signature with OP's federation keys
        _jwt = JWT(key_jar=_federation_entity.keyjar)
        payload = _jwt.unpack(resp)

        # Do I trust the TA the OP chose ?
        _trust_anchor = payload['trust_anchor']
        logger.debug(f"trust_anchor_id: {_trust_anchor}")
        if _trust_anchor not in _federation_entity.function.trust_chain_collector.trust_anchors:
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
            # This is the trust chain from the RP to the TA
            _entity_id = self.upstream_get('attribute', 'entity_id')
            _trust_chains = get_verified_trust_chains(self, entity_id=_entity_id, stop_at=_trust_anchor)

            # should only be one chain
            # should only be one chain
            if len(_trust_chains) == 0:
                raise NoTrustedChains(_entity_id)

            _tcs = [t for t in _trust_chains if t.anchor == _trust_anchor]
            if len(_tcs) > 1:
                raise SystemError(f"More then one chain ending in {_trust_anchor}")
            else:
                _trust_chains = _tcs

            _metadata = payload.get("metadata")
            if _metadata:
                # replace the metadata provided by the client with the metadata received from the AS
                _trust_chains[0].verified_chain[-1]['metadata'] = _metadata
                # If there is metadata_policy defined apply it
                _trust_chains = apply_policies(_federation_entity, _trust_chains)

            _resp = _trust_chains[0].verified_chain[-1]
            _context = self.upstream_get('context')
            _context.registration_response = _resp
            return _resp

    # def update_service_context(self, resp: Union[Message, dict], **kwargs):
    #     """
    #     Updates the service context with information from the Entity Statement return by the server
    #
    #     :param resp: A Entity Statement
    #     :param kwargs: extra key word arguments
    #     """
    #     # Updated service_context per entity type
    #     _root = topmost_unit(self)
    #     _metadata = resp["metadata"]
    #     for guise, item in _root.items():
    #         _guise_metadata = _metadata.get(guise)
    #         if not _guise_metadata:
    #             continue
    #
    #         if isinstance(item, RPHandler):
    #             _behaviour_args = kwargs.get("behaviour_args")
    #             if _behaviour_args:
    #                 _client = _behaviour_args.get("client")
    #                 if _client:
    #                     _context = _client.context
    #                     _context.map_preferred_to_registered(_guise_metadata)
    #
    #                     for arg in ["client_id", "client_secret"]:
    #                         _val = _context.claims.get_usage(arg)
    #                         if _val:
    #                             setattr(_context, arg, _val)
    #
    #                         if arg == "client_secret" and _val:
    #                             _context.keyjar.add_symmetric("", _val)
    #                             _context.keyjar.add_symmetric(_context.claims.get_usage("client_id"), _val)
    #
    #         else:
    #             _context = item.get_context()
    #             _md = self.response_cls(**_guise_metadata)
    #             _md.verify()
    #             _md.weed()
    #             _context.map_preferred_to_registered(_md, uri_claims=RP_URI_CLAIMS)
    #
    #             _client_id = _context.claims.get_usage("client_id")
    #             if _client_id:
    #                 _context.client_id = _client_id
    #
    #             _client_secret = _context.claims.get_usage("client_secret")
    #             _context.keyjar.add_symmetric("", _client_secret)
    #             _context.keyjar.add_symmetric(_client_id, _client_secret)
