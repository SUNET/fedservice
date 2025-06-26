import logging
from typing import List
from typing import Optional

from idpyoidc.message import oidc
from idpyoidc.message.oidc import RegistrationRequest
from idpyoidc.node import topmost_unit
from idpyoidc.server.oidc import authorization

from fedservice.entity.function import apply_policies
from fedservice.entity.function import get_verified_trust_chains
from fedservice.entity.function import verify_trust_chains
from fedservice.entity.utils import get_federation_entity
from fedservice.entity.utils import get_keys
from fedservice.exception import NoTrustedChains

logger = logging.getLogger(__name__)


class Authorization(authorization.Authorization):
    msg_type = oidc.AuthorizationRequest
    response_cls = oidc.AuthorizationResponse
    error_msg = oidc.ResponseMessage

    _supports = authorization.Authorization._supports.copy()
    _supports.update({
        "request_authentication_signing_alg_values_supported": ["RS256"],
        "request_authentication_methods_supported": {
            "authorization_endpoint": [
                "request_object"
            ],
            "pushed_authorization_request_endpoint": [
                "private_key_jwt",
            ]
        }
    })

    def __init__(self, upstream_get, conf: Optional[dict] = None, **kwargs):
        authorization.Authorization.__init__(self, upstream_get, **kwargs)
        # self.pre_construct.append(self._pre_construct)
        self.post_parse_request.append(self._reset_client_id)
        self.new_client_id = kwargs.get('new_client_id', False)
        self.config = conf or {}

    def _reset_client_id(self, request, client_id, context, **kwargs):
        request['client_id'] = client_id
        return request

    def find_client_keys(self, iss):
        return self.do_automatic_registration(iss, [])

    def do_automatic_registration(self, client_entity_id: str, provided_trust_chain: List[str]):
        if provided_trust_chain:
            # So I get the TA's entity statement first
            provided_trust_chain.reverse()
            trust_chains = verify_trust_chains(self, [provided_trust_chain])
            trust_chains = apply_policies(self, trust_chains)
        else:
            trust_chains = get_verified_trust_chains(self, client_entity_id)

        if not trust_chains:
            raise NoTrustedChains()

        # pick one of the possible
        trust_chain = trust_chains[0]
        _fe = get_federation_entity(self)
        _fe.store_trust_chains(client_entity_id, trust_chains)
        # _fe.trust_chain_anchor = trust_chain.anchor

        # handle the registration request as in the non-federation case.
        # If there is a jwks_uri in the metadata import keys
        _root = topmost_unit(self)
        if "openid_provider" in _root:
            get_keys(
                trust_chain.metadata['openid_relying_party'],
                self.upstream_get('attribute', 'keyjar'),
                client_entity_id,
                self)

        req = RegistrationRequest(**trust_chain.metadata['openid_relying_party'])
        req['client_id'] = client_entity_id
        kwargs = {}
        kwargs['new_id'] = self.new_client_id
        kwargs["set_secret"] = False

        op = topmost_unit(self)['openid_provider']
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
        if client_info is None or "automatic_registered" in client_info:
            if 'automatic' in _context.provider_info.get('client_registration_types_supported', []):
                if client_info and "automatic_registered" in client_info:  # Remove the old one
                    del _context.cdb[_cid]
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
                    _context.cdb[registered_client_id]["automatic_registered"] = True
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
