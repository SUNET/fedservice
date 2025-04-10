import json
import logging
import os
from typing import Callable
from typing import List
from typing import Optional
from typing import Union

from cryptojwt.jwt import utc_time_sans_frac
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.key_import import import_jwks
from idpyoidc.server.util import execute
from idpyoidc.util import instantiate

from fedservice.build_entity import FederationEntityBuilder
from fedservice.combo import FederationCombo
from fedservice.defaults import federation_endpoints
from fedservice.defaults import federation_functions
from fedservice.defaults import federation_services
from fedservice.entity import FederationEntity
from fedservice.entity.function import get_verified_jwks

logger = logging.getLogger(__name__)


def statement_is_expired(item):
    now = utc_time_sans_frac()
    if "exp" in item:
        if item["exp"] < now:
            logger.debug(f'is_expired: {item["exp"]} < {now}')
            return True

    return False


def build_entity_config(entity_id: str,
                        key_config: Optional[dict] = None,
                        authority_hints: Optional[Union[List[str], str, Callable]] = None,
                        preference: Optional[dict] = None,
                        endpoints: Optional[list] = None,
                        services: Optional[list] = None,
                        functions: Optional[list] = None,
                        init_kwargs: Optional[dict] = None,
                        item_args: Optional[dict] = None,
                        subordinate: Optional[dict] = None,
                        httpc_params: Optional[dict] = None,
                        persistence: Optional[dict] = None,
                        trust_mark_server: Optional[dict] = None
                        ) -> dict:
    _key_conf = key_config or {"key_defs": DEFAULT_KEY_DEFS}

    if isinstance(authority_hints, dict):
        if "class" in authority_hints and "kwargs" in authority_hints:
            authority_hints = execute(authority_hints)

    entity = FederationEntityBuilder(
        entity_id,
        preference=preference,
        authority_hints=authority_hints,
        key_conf=_key_conf
    )
    for name, items in [("service", services), ("function", functions), ("endpoint", endpoints)]:
        func = getattr(entity, f"add_{name}s")

        if init_kwargs:
            kwargs_spec = init_kwargs.get(name, {})
        else:
            kwargs_spec = None

        if item_args:
            _args = item_args.get(name, {})
        else:
            _args = {}

        if items:
            if name == "service":
                if isinstance(items, dict):
                    # _filtered_spec = {k: v for k, v in items.items() if isinstance(k, str) and
                    # k in SERVICES}
                    func(args=_args, kwargs_spec=kwargs_spec, **items)
                else:
                    func(args=_args, kwargs_spec=kwargs_spec, **federation_services(*items))
            elif name == "function":
                func(args=_args, kwargs_spec=kwargs_spec, **federation_functions(*items))
            elif name == "endpoint":
                if isinstance(items, dict):
                    # _filtered_spec = {k: v for k, v in items.items() if k in FEDERATION_ENDPOINTS}
                    func(args=_args, kwargs_spec=kwargs_spec, **items)
                else:
                    func(args=_args, kwargs_spec=kwargs_spec, **federation_endpoints(*items))
        elif services == []:
            pass
        else:  # There is a difference between None == default and [] which means none
            func(args=_args, kwargs_spec=kwargs_spec)

    if httpc_params:
        entity.conf["httpc_params"] = httpc_params
    if persistence:
        entity.conf["persistence"] = persistence

    return entity.conf


def make_federation_entity(entity_id: str,
                           key_config: Optional[dict] = None,
                           authority_hints: Optional[List[str]] = None,
                           trust_anchors: Optional[dict] = None,
                           preference: Optional[dict] = None,
                           endpoints: Optional[list] = None,
                           services: Optional[Union[list, dict]] = None,
                           functions: Optional[Union[list, dict]] = None,
                           trust_marks: Optional[list] = None,
                           init_kwargs: Optional[dict] = None,
                           item_args: Optional[dict] = None,
                           subordinate: Optional[dict] = None,
                           metadata_policy: Optional[dict] = None,
                           httpc_params: Optional[dict] = None,
                           persistence: Optional[dict] = None,
                           trust_mark_entity: Optional[dict] = None,
                           client_authn_methods: Optional[list] = None,
                           self_signed_trust_mark_entity: Optional[dict] = None,
                           trust_mark_issuers: Optional[dict] = None,
                           trust_mark_owners: Optional[dict] = None
                           ):
    _config = build_entity_config(
        entity_id=entity_id,
        key_config=key_config,
        authority_hints=authority_hints,
        preference=preference,
        endpoints=endpoints,
        services=services,
        functions=functions,
        init_kwargs=init_kwargs,
        item_args=item_args,
        httpc_params=httpc_params,
        persistence=persistence
    )

    fe = FederationEntity(client_authn_methods=client_authn_methods, **_config)
    if trust_anchors:
        if "class" in trust_anchors and "kwargs" in trust_anchors:
            trust_anchors = execute(trust_anchors)

        for id, jwk in trust_anchors.items():
            fe.keyjar = import_jwks(fe.keyjar, jwk, id)

        fe.function.trust_chain_collector.trust_anchors = trust_anchors

    if subordinate:
        if "class" in subordinate and "kwargs" in subordinate:
            fe.server.subordinate = execute(subordinate)
        else:
            for id, info in subordinate.items():
                fe.server.subordinate[id] = info

    if metadata_policy:
        for id, info in metadata_policy.items():
            fe.server.policy[id] = info

    if trust_marks:
        fe.context.trust_marks = trust_marks

    if trust_mark_entity:
        _kwargs = trust_mark_entity.get("kwargs", {})
        _tme = instantiate(trust_mark_entity['class'], upstream_get=fe.unit_get, **_kwargs)
        for name, endp in _tme.endpoint.items():
            fe.server.endpoint[name] = endp
        fe.server.trust_mark_entity = _tme

    if self_signed_trust_mark_entity:
        _kwargs = self_signed_trust_mark_entity.get("kwargs", {})
        _tme = instantiate(self_signed_trust_mark_entity['class'], upstream_get=fe.unit_get,
                           **_kwargs)
        fe.server.self_signed_trust_mark_entity = _tme

    if trust_mark_issuers:
        fe.context.trust_mark_issuers = trust_mark_issuers

    if trust_mark_owners:
        fe.context.trust_mark_owners = trust_mark_owners

    return fe


def make_federation_combo(entity_id: str,
                          key_config: Optional[dict] = None,
                          authority_hints: Optional[List[str]] = None,
                          trust_anchors: Optional[dict] = None,
                          preference: Optional[dict] = None,
                          entity_type: Optional[dict] = None,
                          endpoints: Optional[List[str]] = None,
                          services: Optional[List[str]] = None,
                          functions: Optional[List[str]] = None,
                          subordinate: Optional[dict] = None,
                          metadata_policy: Optional[dict] = None,
                          httpc_params: Optional[dict] = None,
                          init_kwargs: Optional[dict] = None,
                          item_args: Optional[dict] = None,
                          trust_marks: Optional[dict] = None,
                          persistence: Optional[dict] = None,
                          trust_mark_issuers: Optional[dict] = None,
                          trust_mark_owner: Optional[dict] = None,
                          trust_mark_entity: Optional[dict] = None,
                          self_signed_trust_mark_entity: Optional[dict] = None
                          ):
    _config = build_entity_config(
        entity_id=entity_id,
        key_config=key_config,
        authority_hints=authority_hints,
        preference=preference,
        endpoints=endpoints,
        services=services,
        functions=functions,
        httpc_params=httpc_params,
        init_kwargs=init_kwargs,
        item_args=item_args,
        persistence=persistence
    )

    if entity_type:
        entity_config = {
            'entity_id': entity_id,
            "federation_entity": {
                'class': FederationEntity,
                'kwargs': _config
            }
        }
        entity_config.update(entity_type)
        if httpc_params:
            entity_config["httpc_params"] = httpc_params

        entity = FederationCombo(entity_config)
        federation_entity = entity["federation_entity"]
    else:
        entity = FederationEntity(**_config)
        federation_entity = entity

    if trust_anchors:
        if "class" in trust_anchors and "kwargs" in trust_anchors:
            trust_anchors = execute(trust_anchors)

        for id, jwk in trust_anchors.items():
            federation_entity.keyjar = import_jwks(federation_entity.keyjar, jwk, id)

        federation_entity.function.trust_chain_collector.trust_anchors = trust_anchors

    if subordinate:
        if "class" in subordinate and "kwargs" in subordinate:
            federation_entity.server.subordinate = execute(subordinate)
        else:
            for id, info in subordinate.items():
                federation_entity.server.subordinate[id] = info

    if metadata_policy:
        for id, info in metadata_policy.items():
            federation_entity.server.policy[id] = info

    if trust_marks:
        if "class" in trust_marks:
            federation_entity.context.trust_marks = execute(trust_marks)
        else:
            federation_entity.context.trust_marks = trust_marks

    if trust_mark_issuers:
        if "class" in trust_mark_issuers:
            federation_entity.context.trust_mark_issuers = execute(trust_mark_issuers)
        else:
            federation_entity.context.trust_mark_issuers = trust_mark_issuers

    if trust_mark_owner:
        if "class" in trust_mark_owner:
            federation_entity.context.trust_mark_owner = execute(trust_mark_owner)
        else:
            federation_entity.context.trust_mark_owner = trust_mark_owner

    if trust_mark_entity:
        _kwargs = trust_mark_entity.get("kwargs", {})
        _tme = instantiate(trust_mark_entity['class'], upstream_get=federation_entity.unit_get,
                           **_kwargs)
        for name, endp in _tme.endpoint.items():
            federation_entity.server.endpoint[name] = endp
        federation_entity.server.trust_mark_entity = _tme

    if self_signed_trust_mark_entity:
        _kwargs = self_signed_trust_mark_entity.get("kwargs", {})
        _tme = instantiate(self_signed_trust_mark_entity['class'],
                           upstream_get=federation_entity.unit_get, **_kwargs)
        federation_entity.server.self_signed_trust_mark_entity = _tme

    return entity


def _import(val):
    path = val[len("file:"):]
    if os.path.isfile(path) is False:
        logger.info(f"No such file: '{path}'")
        return None

    with open(path, "r") as fp:
        _dat = fp.read()
        if val.endswith('.json'):
            return json.loads(_dat)
        elif val.endswith(".py"):
            return _dat

    raise ValueError("Unknown file type")


def load_values_from_file(config):
    res = {}
    for key, val in config.items():
        if isinstance(val, str) and val.startswith("file:"):
            res[key] = _import(val)
        elif isinstance(val, dict):
            res[key] = load_values_from_file(val)
        elif isinstance(val, list):
            _list = []
            for v in val:
                if isinstance(v, dict):
                    _list.append(load_values_from_file(v))
                elif isinstance(val, str) and val.startswith("file:"):
                    res[key] = _import(val)
                else:
                    _list.append(v)
            res[key] = _list

    for k, v in res.items():
        config[k] = v

    return config


def get_signed_jwks_uri(unit, keyjar, signed_jwks_uri, issuer_id):
    _jwks = get_verified_jwks(unit, signed_jwks_uri)
    if _jwks:
        keyjar = import_jwks(keyjar, _jwks, issuer_id)


def get_jwks(unit, keyjar, metadata, issuer_id):
    if "signed_jwks_uri" in metadata:
        get_signed_jwks_uri(unit, keyjar, metadata["signed_jwks_uri"], issuer_id)
    elif "jwks_uri" in metadata:
        keyjar.add_url(issuer_id, metadata["jwks_uri"])
    elif "jwks" in metadata:
        keyjar = import_jwks(keyjar, metadata["jwks"], issuer_id)
