__author__ = 'Roland Hedberg'

import logging
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from cryptojwt.utils import importer
from idpyoidc.claims import Claims as ClaimsBase
from idpyoidc.client.client_auth import client_auth_setup
from idpyoidc.key_import import import_jwks
from idpyoidc.node import Unit
from idpyoidc.server.util import execute
from idpyoidc.util import instantiate
from requests import request

from fedservice import message
from fedservice.entity.context import FederationContext
from fedservice.entity.function import apply_policies
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import get_verified_trust_chains
from fedservice.entity.function import verify_trust_chains

logger = logging.getLogger(__name__)


class FederationEntityClaims(ClaimsBase):
    _supports = {
        'organization_name': None,
        'contacts': None,
        'policy_uri': None,
        'logo_uri': None,
        'homepage_uri': None,
        'trust_mark_owners': None,
        'trust_mark_issuers': None
    }

    def metadata(self, supports):
        _info = {}
        for key in message.FederationEntity.c_param.keys():
            _val = self.get_preference(key, supports.get(key, None))
            if _val is not None:
                _info[key] = _val
        return _info

    def get_id(self, configuration: dict):
        return ''


class FederationEntity(Unit):
    name = "federation_entity"

    def __init__(self,
                 upstream_get: Optional[Callable] = None,
                 entity_id: str = "",
                 keyjar: Optional[KeyJar] = None,
                 key_conf: Optional[dict] = None,
                 client: Optional[dict] = None,
                 server: Optional[dict] = None,
                 function: Optional[dict] = None,
                 httpc: Optional[object] = None,
                 httpc_params: Optional[dict] = None,
                 preference: Optional[dict] = None,
                 authority_hints: Optional[Union[list, str, Callable]] = None,
                 persistence: Optional[dict] = None,
                 client_authn_methods: Optional[list] = None,
                 **kwargs
                 ):

        if upstream_get is None and httpc is None:
            httpc = request

        if not keyjar and not key_conf:
            keyjar = False

        self.entity_id = entity_id
        Unit.__init__(self, upstream_get=upstream_get, keyjar=keyjar, httpc=httpc,
                      httpc_params=httpc_params, key_conf=key_conf, issuer_id=entity_id)

        _args = {
            "upstream_get": self.unit_get,
            "httpc": self.httpc,
            "httpc_params": self.httpc_params,
            "entity_id": entity_id
        }

        self.client = self.server = self.function = None
        for key, val in [('client', client), ('server', server), ('function', function)]:
            if val:
                _kwargs = val["kwargs"].copy()
                _kwargs.update(_args)
                setattr(self, key, instantiate(val["class"], **_kwargs))

        _args = {}
        for claim in ["trust_mark_issuers", "trust_mark_owners"]:
            _val = kwargs.get(claim)
            if _val:
                _args[claim] = _val

        self.context = FederationContext(entity_id=entity_id, upstream_get=self.unit_get,
                                         authority_hints=authority_hints, keyjar=self.keyjar,
                                         preference=preference, **_args)

        if client_authn_methods:
            self.context.client_authn_methods = client_auth_setup(client_authn_methods)

        self.trust_chain = {}

        self.context.provider_info = self.context.claims.get_server_metadata(
            endpoints=self.server.endpoint.values(),
            metadata_schema=message.FederationEntity,
        )
        self.context.provider_info["issuer"] = self.context.entity_id
        self.context.metadata = self.context.provider_info

        if persistence:
            _storage = execute(persistence["kwargs"]["storage"])
            _class = persistence["class"]
            kwargs = {"storage": _storage, "upstream_get": self.unit_get}
            if isinstance(_class, str):
                self.persistence = importer(_class)(**kwargs)
            else:
                self.persistence = _class(**kwargs)

    def get_context(self, *arg):
        return self.context

    def get_federation_entity(self):
        return self

    def get_entity(self):
        return self

    def get_entity_type(self, entity_type):
        if entity_type == "federation_entity":
            return self
        else:
            return None

    def get_attribute(self, attr, *args):
        try:
            val = getattr(self, attr)
        except AttributeError:
            if self.upstream_get:
                return self.upstream_get('attribute', attr)
            else:
                return None
        else:
            if not val:
                if self.upstream_get:
                    return self.upstream_get('attribute', attr)
                else:
                    return None
            else:
                return val

    def get_function(self, function_name, *args):
        if self.function:
            try:
                return getattr(self.function, function_name)
            except AttributeError:
                return None

    def registration_metadata(self, entity_type="federation_entity", *args):
        _context = self.get_context()
        _claims = _context.claims

        metadata = _claims.get_server_metadata(endpoints=self.get_all_endpoints())

        # remove these from the metadata
        for item in ["jwks", "jwks_uri", "signed_jwks_uri"]:
            try:
                del metadata[item]
            except KeyError:
                pass

        # _issuer = getattr(self.server.context, "trust_mark_server", None)
        return {entity_type: metadata}

    def get_metadata(self, entity_type="federation_entity", *args):
        logger.debug(f"{self.name}:get_metadata")
        _context = self.get_context()
        _claims = _context.claims

        # The entity metadata for a Federation entity server
        metadata = _claims.get_server_metadata(endpoints=self.get_all_endpoints(),
                                               metadata_schema=message.FederationEntity)

        logger.debug(f"metadata:{entity_type} = {metadata}")
        return {entity_type: metadata}

    def get_preferences(self):
        preference = self.get_context().claims.prefer
        # collect endpoints
        preference.update(self.get_endpoint_claims())
        return {"federation_entity": preference}

    def get_all_endpoints(self, *arg):
        if self.server:
            return list(self.server.endpoint.values())
        else:
            return None

    def get_endpoint(self, endpoint_name, *arg):
        if self.server is None:
            return None

        try:
            return self.server.get_endpoint(endpoint_name)
        except KeyError:
            return None

    def get_service(self, service_name, *arg):
        try:
            return self.client.get_service(service_name)
        except KeyError:
            return None

    def get_all_services(self, *args):
        return list(self.client.service.db.keys())

    def get_authority_hints(self, *args):
        return self.context.get_authority_hints()

    def get_trusted_roots(self, *args):
        return self.context.get_trusted_roots()

    def get_context_attribute(self, attr, *args):
        _val = getattr(self.context, attr, None)
        if not _val and self.upstream_get:
            return self.upstream_get('context_attribute', attr)
        else:
            return _val

    def pick_trust_chain(self, trust_chains: list):
        """
        Pick one trust chain out of the list of possible trust chains

        :param trust_chains: A list of :py:class:`fedservice.entity_statement.statement.TrustChain
            instances
        :return: A :py:class:`fedservice.entity_statement.statement.TrustChain instance
        """
        if len(trust_chains) == 1:
            # If there is only one, then use it
            return trust_chains[0]
        elif self.context.tr_priority:
            # Go by priority
            for fid in self.context.tr_priority:
                for trust_chain in trust_chains:
                    if trust_chain.anchor == fid:
                        return trust_chain

        # Can only arrive here if the federations I got back and trust are not
        # in the priority list. So, just pick one
        return trust_chains[0]

    def pick_from_stored_trust_chains(self, entity_id):
        _trust_chains = self.context.trust_chain[entity_id]
        _tas = list(_trust_chains.keys())
        if len(_tas) == 1:
            return _trust_chains[_tas[0]]
        elif self.context.tr_priority:
            # Go by priority
            for ta_id in self.context.tr_priority:
                for ta_id in _tas:
                    return _trust_chains[ta_id]
        return _trust_chains[_tas[0]]

    # def get_payload(self, self_signed_statement):
    #     _jws = as_unicode(self_signed_statement)
    #     _jwt = factory(_jws)
    #     return _jwt.jwt.payload()

    def supported(self):
        _supports = self.context.supports()
        if self.server:
            _supports.update(self.server.context.supports())
        return _supports

    def get_endpoint_claims(self):
        _info = {}
        for endp in self.server.endpoint.values():
            if endp.endpoint_name:
                _info[endp.endpoint_name] = endp.full_path
                for arg, claim in [("client_authn_method", "auth_methods"),
                                   ("auth_signing_alg_values", "auth_signing_alg_values")]:
                    _val = getattr(endp, arg, None)
                    if _val:
                        # trust_mark_status_endpoint_auth_methods_supported
                        md_param = f"{endp.endpoint_name}_{claim}"
                        _info[md_param] = _val
        return _info

    def get_trust_chains(self, entity_id):
        _trust_chains = self.trust_chain.get(entity_id, None)
        if _trust_chains is None:
            _trust_chains = get_verified_trust_chains(self, entity_id)
            if _trust_chains:
                self.store_trust_chain(entity_id, _trust_chains)
            else:
                return []

        return _trust_chains

    def store_trust_chain(self, entity_id, trust_chains):
        self.trust_chain[entity_id] = trust_chains

    def store_trust_chains(self, entity_id, chains):
        self.trust_chain[entity_id] = chains

    def get_verified_metadata(self, entity_id: str, *args):
        _trust_chains = self.trust_chain.get(entity_id)
        if _trust_chains is None:
            _trust_chains = get_verified_trust_chains(self, entity_id)
            if _trust_chains:
                self.store_trust_chain(entity_id, _trust_chains)

        if _trust_chains:
            return _trust_chains[0].metadata
        else:
            return None

    def get_federation_entity_metadata(self, entity_id: str, *args):
        metadata = self.get_verified_metadata(entity_id, *args)
        if metadata:
            return metadata["federation_entity"]
        else:
            return metadata

    def do_request(
            self,
            request_type: str,
            response_body_type: Optional[str] = "",
            request_args: Optional[dict] = None,
            behaviour_args: Optional[dict] = None,
            **kwargs):
        return self.client.do_request(request_type=request_type,
                                      response_body_type=response_body_type,
                                      request_args=request_args, behaviour_args=behaviour_args,
                                      **kwargs)

    def trawl(self, superior, subordinate, entity_type):
        if subordinate in self.function.trust_chain_collector.config_cache:
            _ec = self.function.trust_chain_collector.config_cache[subordinate]
        else:
            _es = self.client.do_request("entity_statement", issuer=superior, subject=subordinate)

            # add subjects key/-s to keyjar
            _kj = self.get_federation_entity().keyjar
            _kj = import_jwks(_kj, _es["jwks"], _es["sub"])

            # Fetch Entity Configuration
            _ec = self.client.do_request("entity_configuration", entity_id=subordinate)

        if entity_type in _ec["metadata"]:
            _issuers = [_ec["sub"]]
        else:
            _issuers = []

        if "federation_list_endpoint" not in _ec["metadata"]["federation_entity"]:
            return _issuers

        # One step down the tree
        # All subordinates that are of a specific entity_type
        _added_issuers = self.client.do_request("list",
                                                entity_id=subordinate,
                                                entity_type=entity_type)
        if _added_issuers is None:
            pass
        else:
            _issuers.extend(_added_issuers)

        # All subordinates that are intermediates
        _intermediates = self.client.do_request("list",
                                                entity_id=subordinate,
                                                intermediate=True)

        # For all intermediates go further down the tree
        if _intermediates:
            for entity_id in _intermediates:
                _ids = self.trawl(subordinate, entity_id, entity_type)
                if _ids:
                    _issuers.extend(_ids)

        return _issuers

    def verify_trust_mark(self, trust_mark: str, check_with_issuer: Optional[bool] = True):
        _trust_mark_payload = get_payload(trust_mark)
        _tmi_trust_chains = self.get_trust_chains(_trust_mark_payload['iss'])
        if not _tmi_trust_chains:
            return None

        _tmi_trust_chain = _tmi_trust_chains[0]

        # Verifies the signature of the Trust Mark
        verified_trust_mark = self.function.trust_mark_verifier(
            trust_mark=trust_mark, trust_anchor=_tmi_trust_chain.anchor)

        if check_with_issuer:
            # This to check that the Trust Mark is still valid according to the Trust Mark Issuer
            resp = self.do_request("trust_mark_status",
                                   request_args={
                                       'sub': verified_trust_mark['sub'],
                                       'trust_mark_id': verified_trust_mark['trust_mark_id']
                                   },
                                   fetch_endpoint=_tmi_trust_chain.metadata["federation_entity"][
                                       "federation_trust_mark_status_endpoint"]
                                   )
            if "active" in resp and resp["active"] == True:
                pass
            else:
                return None

        return verified_trust_mark

    @property
    def trust_anchors(self):
        return self.get_function("trust_chain_collector").trust_anchors

    @trust_anchors.setter
    def trust_anchors(self, value):
        self.get_function("trust_chain_collector").trust_anchors = value

    def add_trust_anchor(self, entity_id, jwks):
        if self.keyjar:
            _keyjar = self.keyjar
        elif self.upstream_get:
            _keyjar = self.upstream_get('attribute', 'keyjar')
        else:
            raise ValueError("Missing keyjar")

        _keyjar = import_jwks(_keyjar, jwks, entity_id)
        self.trust_anchors[entity_id] = jwks

    def supports(self):
        res = {}
        for name, service in self.client.service.items():
            res.update(service.supports())

        for name, endp in self.server.endpoint.items():
            res.update(endp.supports())

        res.update(self.context.claims._supports)
        return res
