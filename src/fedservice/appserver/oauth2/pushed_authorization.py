import logging
from typing import List

from fedservice.appserver import import_client_keys
from fedservice.entity.function import get_verified_trust_chains
from idpyoidc.message import oauth2
from idpyoidc.node import topmost_unit
from idpyoidc.server.oauth2.authorization import Authorization
from idpyoidc.server.oauth2 import authorization

from fedservice.entity.function import apply_policies
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import verify_trust_chains
from fedservice.entity.utils import get_federation_entity
from fedservice.exception import NoTrustedChains
from fedservice.message import OauthClientMetadata

logger = logging.getLogger(__name__)


class PushedAuthorization(Authorization):
    request_cls = oauth2.PushedAuthorizationRequest
    response_cls = oauth2.Message
    endpoint_name = "pushed_authorization_request_endpoint"
    request_placement = "body"
    request_format = "urlencoded"
    response_placement = "body"
    response_format = "json"
    name = "pushed_authorization"
    endpoint_type = "oauth2"

    def __init__(self, upstream_get, **kwargs):
        Authorization.__init__(self, upstream_get, **kwargs)
        # self.pre_construct.append(self._pre_construct)
        self.post_parse_request.append(self._post_parse_request)
        self.ttl = kwargs.get("ttl", 3600)
        self.new_client_id = ""
        # When a signed JWT is used as client credentials this matches the "aud"
        # default self.allowed_targets = [self.name]
        self.allowed_targets.append("")

    def find_client_keys(self, iss):
        return self.do_automatic_registration(iss, [])

    def do_automatic_registration(self, entity_id: str, provided_trust_chain: List[str]):
        if provided_trust_chain:
            # So I get the TA's entity statement first
            provided_trust_chain.reverse()
            trust_chains = verify_trust_chains(self, [provided_trust_chain])
            trust_chains = apply_policies(self, trust_chains)
        else:
            trust_chains = get_verified_trust_chains(self, entity_id)

        if not trust_chains:
            raise NoTrustedChains()

        # pick one of the possible
        trust_chain = trust_chains[0]
        _fe = topmost_unit(self)['federation_entity']
        _fe.trust_chain_anchor = trust_chain.anchor

        _metadata = trust_chain.metadata['oauth_client']

        # If there is a signed_jwks_uri, jwks_uri or jwks in the metadata import the keys
        import_client_keys(_metadata, self.upstream_get('attribute', 'keyjar'), entity_id)

        req = OauthClientMetadata(**_metadata)
        req['client_id'] = entity_id
        kwargs = {}
        if self.new_client_id:
            kwargs['new_id'] = self.new_client_id

        op = topmost_unit(self)['oauth_authorization_server']
        _registration = op.get_endpoint("registration")
        response_info = _registration.non_fed_process_request(req=req, **kwargs)

        try:
            return response_info["response_args"]["client_id"]
        except KeyError:
            return None

    def client_authentication(self, request, auth=None, **kwargs):
        _cid = request["client_id"]
        _context = self.upstream_get("context")
        # If this is a registered client then this should return some info
        client_info = _context.cdb.get(_cid)
        if client_info is None:
            if 'automatic' in _context.provider_info.get('client_registration_types_supported'):
                # try the federation way
                _trust_chain = request.get('trust_chain', [])
                registered_client_id = self.do_automatic_registration(_cid, _trust_chain)
                if registered_client_id is None:
                    return {
                        'error': 'unauthorized_client',
                        'error_description': 'Unknown client'
                    }
                else:
                    logger.debug('Automatic registration done')
                    if registered_client_id != _cid:
                        request["client_id"] = registered_client_id
                        kwargs["also_known_as"] = {_cid: registered_client_id}
                        client_info = _context.cdb[registered_client_id]
                        _context.cdb[_cid] = client_info
                        client_info['entity_id'] = _cid
                        # _context.cdb[registered_client_id] = client_info
            else:
                return {
                    'error': 'unauthorized_client',
                    'error_description': 'Unknown client'
                }

        # then do client authentication
        return authorization.Authorization.client_authentication(
            self, request, auth, **kwargs)

    def extra_response_args(self, aresp, **kwargs):
        _fe = get_federation_entity(self)
        _client_id = kwargs.get('client_id')
        if _client_id:
            _tcs = _fe.trust_chain.get(_client_id, {})
            if _tcs:
                aresp['trust_anchor'] = _tcs[0].anchor
        return aresp
