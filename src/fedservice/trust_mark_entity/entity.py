import logging
from typing import Callable
from typing import Optional

from cryptojwt import JWT
from cryptojwt.jwt import utc_time_sans_frac
from cryptojwt.key_jar import init_key_jar
from idpyoidc.node import Unit
from idpyoidc.server import do_endpoints
from idpyoidc.server.client_authn import CLIENT_AUTHN_METHOD
from idpyoidc.server.endpoint_context import init_service

from fedservice.entity.utils import get_federation_entity
from fedservice.message import TrustMark
from fedservice.trust_mark_entity import SimpleDB
from fedservice.trust_mark_entity.context import TrustMarkContext


logger = logging.getLogger(__name__)

def create_trust_mark(keyjar, entity_id, **kwargs):
    packer = JWT(key_jar=keyjar, iss=entity_id)
    return packer.pack(payload=kwargs)


class TrustMarkEntity(Unit):
    name = 'trust_mark_entity'

    def __init__(self,
                 entity_id: str = "",
                 upstream_get: Optional[Callable] = None,
                 trust_mark_specification: Optional[dict] = None,
                 trust_mark_db: Optional[dict] = None,
                 endpoint: Optional[dict] = None,
                 **kwargs
                 ):

        Unit.__init__(self, upstream_get=upstream_get)

        self.entity_id = entity_id or upstream_get("attribute", "entity_id")
        self.endpoint = do_endpoints({"endpoint": endpoint, "issuer": self.entity_id},
                                     self.unit_get)
        self.trust_mark_specification = trust_mark_specification or {}

        self.tm_lifetime = {}
        for entity_id, tm in self.trust_mark_specification.items():
            if "lifetime" in tm:
                self.tm_lifetime[entity_id] = tm["lifetime"]
                del tm["lifetime"]

        if trust_mark_db:
            self.issued = init_service(trust_mark_db)
        else:
            self.issued = SimpleDB()

        _key_conf = kwargs.get("key_conf", None)
        if _key_conf:
            self.keyjar = init_key_jar(**_key_conf)
        else:
            self.keyjar = None

        auth_set = {}
        for name, endp in self.endpoint.items():
            if endp.client_authn_method:
                for _meth in endp.client_authn_method:
                    auth_set[_meth] = CLIENT_AUTHN_METHOD[_meth](self.unit_get)

        self.context = TrustMarkContext(client_authn_methods=auth_set)

    def create_trust_mark(self, id: [str], sub: [str], **kwargs) -> str:
        """

        :param id: Trust Mark identifier
        :param sub: The receiver of the Trust Mark
        :param kwargs: extra claims to be added to the Trust Mark's claims
        :return: Trust Mark
        """
        _now = utc_time_sans_frac()
        _add = {'iat': _now, 'trust_mark_id': id, 'sub': sub}
        lifetime = self.tm_lifetime.get(id)
        if lifetime:
            _add['exp'] = _now + lifetime

        if id not in self.trust_mark_specification:
            raise ValueError('Unknown trust mark ID')

        content = self.trust_mark_specification[id].copy()
        content.update(_add)
        if kwargs:
            content.update(kwargs)
        self.issued.add(content)

        _federation_entity = get_federation_entity(self)
        packer = JWT(key_jar=_federation_entity.keyjar, iss=_federation_entity.entity_id)
        return packer.pack(payload=content)

    def dump_trust_marks(self):
        return self.issued.dumps()

    def load_trust_marks(self, marks):
        return self.issued.loads(marks)

    def unpack_trust_mark(self, token, entity_id: Optional[str] = ""):
        keyjar = self.upstream_get('attribute', 'keyjar')
        _jwt = JWT(key_jar=keyjar, msg_cls=TrustMark, allowed_sign_algs=["RS256"])
        _tm = _jwt.unpack(token)

        if entity_id:
            _tm.verify(entity_id=entity_id)
        else:
            _tm.verify()

        return _tm

    def self_signed_trust_mark(self, **kwargs):
        _entity_id = self.upstream_get("attribute", 'entity_id')
        _keyjar = self.upstream_get('attribute', 'keyjar')

        packer = JWT(key_jar=_keyjar, iss=_entity_id)
        if 'sub' not in kwargs:
            kwargs['sub'] = _entity_id
        return packer.pack(payload=kwargs)

    def find(self, trust_mark_id, sub: str, iat: Optional[int] = 0) -> bool:
        return self.issued.find(trust_mark_id=trust_mark_id, sub=sub, iat=iat)

    def list(self, trust_mark_id: str, sub: Optional[str] = "") -> list:
        if sub:
            if self.find(trust_mark_id, sub):
                return [sub]
        else:
            return self.issued.list(trust_mark_id)

    def get_metadata(self):
        logger.debug(f"{self.name}:get_metadata")
        # three endpoints
        md = {}
        for name, endp in self.endpoint.items():
            if endp.full_path:
                md[f"{endp.name}_endpoint"] = endp.full_path
            for arg, txt in [("auth_signing_alg_values", "auth_signing_algs"),
                             ("client_authn_method", "auth_methods")]:
                _val = getattr(endp, arg, None)
                if _val:
                    md[f"{endp.name}_{txt}"] = _val
        logger.debug(f"metadata:{self.name} = {md}")
        return {self.name: md}

    def get_context(self, *args):
        return self.context

    def get_endpoint(self, endpoint_name, **args):
        return self.endpoint[endpoint_name]


class SelfSignedTrustMarkEntity(Unit):
    name = 'self_signed_trust_mark_entity'

    def __init__(self,
                 entity_id: str = "",
                 upstream_get: Optional[Callable] = None,
                 trust_mark_ids: Optional[list] = None,
                 trust_mark_specification: Optional[dict] = None,
                 **kwargs
                 ):

        Unit.__init__(self, upstream_get=upstream_get)

        self.entity_id = entity_id or upstream_get("attribute", "entity_id")
        self.trust_mark_ids = trust_mark_ids or []
        self.trust_mark_specification = trust_mark_specification or {}
        self.issued = []
        self.tm_lifetime = 86400*30

    def __call__(self, id: [str], **kwargs) -> str:
        """

        :param id: Trust Mark identifier
        :param sub: The receiver of the Trust Mark
        :param kwargs: extra claims to be added to the Trust Mark's claims
        :return: Trust Mark
        """
        _now = utc_time_sans_frac()
        sub = self.upstream_get('attribute', 'entity_id')
        _add = {'iat': _now, 'trust_mark_id': id, 'sub': sub}
        lifetime = self.tm_lifetime
        if lifetime:
            _add['exp'] = _now + lifetime

        if id not in self.trust_mark_specification:
            raise ValueError('Unknown trust mark ID')

        content = self.trust_mark_specification[id].copy()
        content.update(_add)
        if kwargs:
            content.update(kwargs)
        self.issued.append(content)

        _federation_entity = get_federation_entity(self)
        packer = JWT(key_jar=_federation_entity.keyjar, iss=_federation_entity.entity_id)
        _trust_mark = packer.pack(payload=content)
        entity = self.upstream_get("unit")
        entity.context.trust_marks.append(_trust_mark)

        return _trust_mark

