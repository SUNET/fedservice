import logging
from typing import Optional
from typing import Union

from cryptojwt import JWT
from cryptojwt.jws.jws import factory
from idpyoidc.client.exception import ResponseError
from idpyoidc.client.oidc import registration
from idpyoidc.client.oidc.rp import RP
from idpyoidc.client.service import Service
from idpyoidc.message import Message
from idpyoidc.message.oidc import RegistrationRequest
from idpyoidc.node import topmost_unit
from idpyoidc.transform import RP_URI_CLAIMS

from fedservice.entity import get_federation_entity_keyjar
from fedservice.entity.function import apply_policies
from fedservice.entity.function import get_verified_trust_chains
from fedservice.entity.function import verify_entity_statement
from fedservice.entity.utils import get_federation_entity
from fedservice.exception import NoTrustedChains
from fedservice.message import ExplicitRegistrationResponse
from fedservice.message import FedASConfigurationResponse
from fedservice.message import OauthClientMetadata
from fedservice.message import OIDCRPMetadata
from fedservice.message import OPMetadata

logger = logging.getLogger(__name__)


def create_entity_configuration(request_args: Optional[dict] = None, service: Optional[Service] = None,
                                server_entity_id: Optional[str] = '', **kwargs):
    _combo = topmost_unit(service)

    metadata = _combo.get_metadata(server_entity_id=server_entity_id)
    entity_types = [k for k in _combo.keys() if k != "federation_entity"]
    # Assumes there is only one part in the entity except for the federation entity
    metadata[entity_types[0]].update({k:v for k,v in request_args.items() if k != "entity_id"})

    federation_entity = get_federation_entity(service)

    _federation_keyjar = federation_entity.context.keyjar
    _authority_hints = federation_entity.get_authority_hints()
    _context = federation_entity.get_context()
    _entity_id = _context.entity_id

    kwargs = {}
    if _context.trust_marks:
        kwargs["trust_marks"] = _context.get_trust_marks()

    _jws = _context.create_entity_configuration(
        iss=_entity_id,
        # sub=_entity_id,
        metadata=metadata,
        key_jar=_federation_keyjar,
        authority_hints=_authority_hints,
        **kwargs)
    # store for later reference
    federation_entity.entity_configuration = _jws
    return _jws


def create_explicit_registration_request(request_args: Optional[dict] = None,
                                         service: Optional[Service] = None,
                                         **kwargs):
    """

    :param request_args:
    :param service:
    :param kwargs:
    :return:
    """

    _combo = topmost_unit(service)
    metadata = _combo.get_metadata(client=kwargs.get("client"))
    federation_entity = get_federation_entity(service)

    _federation_keyjar = federation_entity.context.keyjar
    _authority_hints = federation_entity.get_authority_hints()
    _context = federation_entity.get_context()
    _entity_id = federation_entity.upstream_get('attribute', 'entity_id')

    _trust_chain = kwargs.get("trust_chain", None)

    _args = {}
    if _context.trust_marks:
        _args["trust_marks"] = _context.get_trust_marks()

    # for claim in ["aud"] and request_args != None:
    #     _args[claim] = request_args.get(claim)

    if _trust_chain:
        # peer = _args["aud"]
        # leaf = federation_entity.context.entity_id
        # trust_chain, peer_trust_chain = with_common_trust_anchor(_context, leaf, peer)
        # if trust_chain is None:
        #     raise ValueError("Could not find two trust chains with the same TA")
        jws_header_param = {
            "peer_trust_chain": kwargs.get('peer_trust_chain'),
            "trust_chain": _trust_chain
        }
    else:
        jws_header_param = {}

    if service.application_protocol == "oauth2":
        raise ValueError("No OAuth2 support for explicit registration")

    _jws = _context.create_explicit_registration_request(
        iss=_entity_id,
        metadata=metadata,
        key_jar=_federation_keyjar,
        authority_hints=_authority_hints,
        jws_header_param=jws_header_param,
        **_args)

    # store for later reference
    federation_entity.entity_configuration = _jws
    return _jws


def parse_federation_registration_response(service, resp, **kwargs):
    """
    Receives a dynamic client registration response,

    :param resp: An entity statement as a signed JWT
    :return: A set of metadata claims
    """

    # Find the part of me that deals with the federation
    federation_entity = get_federation_entity(service)

    _trust_anchors = list(federation_entity.context.trust_anchors.keys())
    _sub = kwargs.get("sub") or federation_entity.context.entity_id

    entity_config = verify_entity_statement(resp, _sub, trust_anchors=_trust_anchors,
                                            keyjar=get_federation_entity_keyjar(service),
                                            msg_type='registration_response')

    # This is where I should decide to use the metadata verification service or do it
    # all myself
    # Do I have the necessary Function/Service installed
    _verifier = federation_entity.get_function("metadata_verifier")
    if _verifier:
        #  construct the query, send it and parse the response
        _verifier_response = _verifier(resp)
        if _verifier_response:
            return _verifier_response
    else:
        # This is the trust chain from myself to the TA
        _trust_anchor = entity_config.get("trust_anchor", "")
        entity_id = service.upstream_get('attribute', 'entity_id')
        _trust_chains = get_verified_trust_chains(service, entity_id=entity_id, stop_at=_trust_anchor)

        # should only be one chain
        if len(_trust_chains) == 0:
            raise NoTrustedChains(entity_id)

        _tcs = [t for t in _trust_chains if t.anchor == _trust_anchor]
        if len(_tcs) > 1:
            raise SystemError(f"More then one chain ending in {_trust_anchor}")
        else:
            _trust_chains = _tcs

        _metadata = entity_config.get("metadata")
        if _metadata:
            # replace the metadata provided by the client with the metadata received from the AS
            _trust_chains[0].verified_chain[-1]['metadata'] = _metadata
            # If there is metadata_policy defined apply it
            _trust_chains = apply_policies(federation_entity, _trust_chains)

        _resp = _trust_chains[0].verified_chain[-1]
        _context = service.upstream_get('context')
        _context.registration_response = _resp
        return _resp


def shared_update_service_context(service, resp, **kwargs):
    # Updated service_context per entity type
    _root = topmost_unit(service)
    _metadata = resp["metadata"]
    for guise, item in _root.items():
        _guise_metadata = _metadata.get(guise)
        if not _guise_metadata:
            continue

        if isinstance(item, RP):
            _behaviour_args = kwargs.get("behaviour_args")
            if _behaviour_args:
                _client = _behaviour_args.get("client")
            else:
                _client = item

            if _client:
                _context = _client.context[resp['iss']]
                _md = _client.metadata_class(**_guise_metadata)
                _context.map_preferred_to_registered(_guise_metadata, uri_claims=service.uri_claims)

                for arg in ["client_id", "client_secret"]:
                    _val = _context.claims.get_usage(arg)
                    if _val:
                        setattr(_context, arg, _val)

                    if arg == "client_secret" and _val:
                        _context.keyjar.add_symmetric("", _val)
                        _context.keyjar.add_symmetric(_context.claims.get_usage("client_id"), _val)
        else:
            _context = item.get_context()
            _md = service.metadata_cls[guise](**_guise_metadata)
            _md.verify()
            _md.weed()
            _context.map_preferred_to_registered(_md, service.uri_claims)

            _client_id = _context.claims.get_usage("client_id")
            if _client_id:
                _context.client_id = _client_id


def post_construct_create_entity_configuration(context,
                                               request_args: Optional[dict] = None,
                                               service: Optional[Service] = None, **kwargs):
    """
    Wrapper to deal with context
    :param context:
    :param request_args:
    :param service:
    :param kwargs:
    :return:
    """
    server_entity_id = context.issuer
    return create_entity_configuration(request_args, service,  server_entity_id=server_entity_id, **kwargs)


class Registration(registration.Registration):
    msg_type = RegistrationRequest
    response_cls = ExplicitRegistrationResponse
    metadata_cls = {'openid_relying_party': OIDCRPMetadata,
                    'oauth_client': OauthClientMetadata,
                    'oauth_authorization_server': FedASConfigurationResponse,
                    'openid_provider': OPMetadata}
    endpoint_name = 'federation_registration_endpoint'
    request_body_type = 'jwt'
    response_body_type = 'jwt'
    content_type = "application/explicit-registration-response+jwt"
    name = 'registration'
    application_protocol = "oidc"
    payload_type = 'explicit-registration-response+jwt'

    _supports = {
        "client_registration_types": ["automatic", "explicit"]
    }

    uri_claims = RP_URI_CLAIMS

    def __init__(self, upstream_get, conf=None, client_authn_factory=None, **kwargs):
        registration.Registration.__init__(self, upstream_get, conf=conf)
        #
        self.post_construct.append(post_construct_create_entity_configuration)

    @staticmethod
    def carry_receiver(request, **kwargs):
        if 'receiver' in kwargs:
            return request, {'receiver': kwargs['receiver']}
        else:
            return request, {}

    def update_service_context(self, context, resp: Union[Message, dict], **kwargs):
        shared_update_service_context(service=self, resp=resp, **kwargs)

    def create_entity_statement(self, request_args: Optional[dict] = None, **kwargs):
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
            kwargs["key_jar"] = _context.keyjar

        _jws = _context.create_entity_configuration(iss=_federation_entity.context.entity_id, **kwargs)
        return _jws

    def parse_response(self, context, info, sformat="", state="", **kwargs):
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

        # Find the part of the system that deals with the federation
        _federation_entity = get_federation_entity(self)

        # Verify payload type
        if self.payload_type:
            _jws = factory(resp)
            if _jws is None:
                raise ValueError('Response NOT a signed JWT')
            if _jws.jwt.headers['typ'] != self.payload_type:
                raise ValueError('Expected payload type did not matched received')

        # verify signature with OP's federation keys
        _jwt = JWT(key_jar=_federation_entity.context.keyjar)
        payload = _jwt.unpack(resp)

        # Do I trust the TA the OP chose ?
        _trust_anchor = payload['trust_anchor']
        logger.debug(f"trust_anchor_id: {_trust_anchor}")
        if _trust_anchor not in _federation_entity.context.trust_anchor:
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
                # replace the metadata collected with the trust chain with the metadata received from the AS/OP
                _trust_chains[0].verified_chain[-1]['metadata'] = _metadata
                # If there is metadata_policy defined apply it
                _trust_chains = apply_policies(_federation_entity, _trust_chains)

            _resp = _trust_chains[0].verified_chain[-1]
            _resp['iss'] = payload['iss']
            _context = self.upstream_get('context')
            _context.registration_response = _resp
            return _resp
