import json
from typing import Callable
from typing import List
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from idpyoidc.client.client_auth import client_auth_setup
from idpyoidc.configure import Configuration
from idpyoidc.impexp import ImpExp
from idpyoidc.transform import preferred_to_registered

from fedservice.entity.claims import FederationEntityClaims
from fedservice.entity_statement.create import create_entity_statement


def entity_type(metadata):
    # assuming there is only one type apart from federation_entity and trust_mark_issuer
    return set(metadata.keys()).difference({'federation_entity', 'trust_mark_issuer'}).pop()


class FederationContext(ImpExp):
    parameter = ImpExp.parameter.copy()
    parameter.update({
        "default_lifetime": 0,
        "authority_hints": [],
        "tr_priority": [],
        "trust_mark_issuer": None,
        "trust_mark_owners": None,
        "signed_trust_marks": [],
        "trust_marks": [],
    })

    def __init__(self,
                 config: Optional[Union[dict, Configuration]] = None,
                 entity_id: str = "",
                 upstream_get: Callable = None,
                 default_lifetime: Optional[int] = 86400,
                 priority: Optional[list] = None,
                 trust_marks: Optional[list] = None,
                 trusted_roots: Optional[Union[str, dict, Callable]] = None,
                 authority_hints: Optional[Union[list, str, Callable]] = None,
                 keyjar: Optional[KeyJar] = None,
                 preference: Optional[dict] = None,
                 trust_mark_issuers: Optional[dict] = None,
                 trust_mark_owners: Optional[dict] = None,
                 **kwargs
                 ):

        ImpExp.__init__(self)

        if config is None:
            config = {}

        self.config = config
        self.upstream_get = upstream_get
        self.entity_id = entity_id or config.get("entity_id",
                                                 self.upstream_get("attribute", "entity_id"))
        self.default_lifetime = default_lifetime or config.get("default_lifetime", 0)

        self.trust_marks = trust_marks or config.get('trust_marks', [])
        self.trusted_roots = trusted_roots or config.get('trusted_roots', {})
        self.authority_hints = authority_hints or config.get('authority_hints', [])
        self.trust_mark_issuers = trust_mark_issuers or config.get('trust_mark_issuers', {})
        self.trust_mark_owners = trust_mark_owners or config.get('trust_mark_owners', {})
        self.trusted_roots = trusted_roots or config.get('trusted_roots', {})

        self.trust_chain = {}
        # self.issuer = self.entity_id

        self.claims = FederationEntityClaims(prefer=preference)

        if priority:
            self.tr_priority = priority
        elif 'priority' in config:
            self.tr_priority = config["priority"]
        else:
            self.tr_priority = sorted(set(self.get_trusted_roots().keys()))

        for param, default in self.parameter.items():
            _val = kwargs.get(param)
            if _val is not None:
                setattr(self, param, _val)
            else:
                try:
                    getattr(self, param)
                except AttributeError:
                    setattr(self, param, default)

        if preference:
            config['preference'] = preference
        _keyjar = self.claims.load_conf(config, supports=self.supports(), keyjar=keyjar)

        if self.upstream_get:
            _unit = self.upstream_get('unit')
            _unit.keyjar = _keyjar
        else:
            self.keyjar = _keyjar

        self.setup_client_authn_methods()

        # For backward compatibility
        self.kid = {"sig": {}, "enc": {}}

    def supports(self):
        return self.claims._supports

    def setup_client_authn_methods(self):
        self.client_authn_methods = client_auth_setup(self.config.get("client_authn_methods"))

    def create_entity_statement(self, iss, sub, key_jar=None, metadata=None, metadata_policy=None,
                                authority_hints=None, lifetime=0, jwks=None, **kwargs):
        if jwks:
            kwargs["jwks"] = jwks
        else:
            if "keys" in kwargs:
                kwargs["jwks"] = {'keys': kwargs["keys"]}
                del kwargs["keys"]

        key_jar = key_jar or self.upstream_get("attribute", "keyjar")

        if not authority_hints:
            authority_hints = self.authority_hints
        if not lifetime:
            lifetime = self.default_lifetime

        _trust_marks = kwargs.get("trust_marks")
        if not _trust_marks:
            _trust_marks = self.get_trust_marks()
        if _trust_marks:
            kwargs["trust_marks"] = _trust_marks

        return create_entity_statement(iss, sub, key_jar=key_jar, metadata=metadata,
                                       metadata_policy=metadata_policy,
                                       authority_hints=authority_hints, lifetime=lifetime, **kwargs)

    def map_preferred_to_registered(self, registration_response: Optional[dict] = None):
        self.claims.use = preferred_to_registered(
            self.claims.prefer,
            supported=self.supports(),
            registration_response=registration_response,
        )

        return self.claims.use

    def get_authority_hints(self, *args) -> list:
        _hints = self.authority_hints
        if isinstance(_hints, list):
            return _hints
        elif isinstance(_hints, str):
            return json.loads(open(_hints, "r").read())
        elif isinstance(_hints, Callable):
            return _hints()
        else:
            raise ValueError("authority_hints")

    def get_trusted_roots(self) -> dict:
        if self.trusted_roots is None:
            # Must be trust anchor then
            return {}
        elif isinstance(self.trusted_roots, str):
            return json.loads(open(self.trusted_roots).read())
        elif isinstance(self.trusted_roots, dict):
            return self.trusted_roots
        elif isinstance(self.trusted_roots, Callable):
            return self.trusted_roots()
        else:
            raise ValueError("trusted_roots")

    def get_trust_marks(self)-> Optional[list]:
        if self.trust_marks == None:
            return []
        elif isinstance(self.trust_marks, str):
            return json.loads(open(self.trust_marks).read())
        elif isinstance(self.trust_marks, list):
            return self.trust_marks
        elif isinstance(self.trust_marks, Callable):
            return self.trust_marks()
        else:
            raise ValueError("trust_marks")


class FederationServerContext(FederationContext):

    def __init__(self,
                 config: Optional[Union[dict, Configuration]] = None,
                 entity_id: str = "",
                 upstream_get: Callable = None,
                 preference: Optional[dict] = None,
                 trust_marks: Optional[List[str]] = None,
                 authority_hints: Optional[list] = None,
                 ):
        FederationContext.__init__(self,
                                   config=config,
                                   entity_id=entity_id,
                                   upstream_get=upstream_get,
                                   preference=preference,
                                   authority_hints=authority_hints,
                                   )

        _sstm = config.get("self_signed_trust_marks")
        if _sstm:
            _keyjar = upstream_get('attribute', "keyjar")
            self.signed_trust_marks = self.create_entity_statement(iss=self.entity_id,
                                                                   sub=self.entity_id,
                                                                   keyjar=_keyjar,
                                                                   trust_marks=_sstm)

        self.trust_marks = trust_marks
        self.jti_db = {}
