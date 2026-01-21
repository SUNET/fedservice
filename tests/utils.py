import json
from typing import Callable
from typing import List
from typing import Optional
from urllib.parse import urlparse

from cryptojwt.key_jar import KeyJar

from fedservice.entity import get_federation_entity_keyjar
from fedservice.entity.utils import get_federation_entity

from fedservice.entity.function import Function
from fedservice.entity.function.trust_chain_collector import cache_key
from fedservice.entity.function.trust_chain_collector import unverified_entity_statement
from fedservice.entity.function.trust_chain_collector import verify_self_signed_signature
from fedservice.fetch_entity_statement.fs2 import FSFetchEntityStatement


def load_trust_roots(trust_root_file):
    trust_roots = json.loads(open(trust_root_file).read())
    kj = KeyJar()
    for iss, jwks in trust_roots.items():
        kj.import_jwks(jwks, iss)
    return kj


def get_netloc(url):
    p = urlparse(url)
    return p.netloc


class DummyCollector(Function):

    def __init__(self,
                 trust_anchors: dict,
                 upstream_get: Optional[Callable] = None,
                 keyjar: Optional[KeyJar] = None,
                 root_dir: Optional[str] = '.',
                 base_url: Optional[str] = '',
                 **kwargs):
        Function.__init__(self, upstream_get=upstream_get)
        self.trust_anchors = trust_anchors

        self.root_dir = root_dir
        self.base_url = base_url

        if keyjar:
            self.keyjar = keyjar
        else:
            self.keyjar = None
            keyjar = get_federation_entity_keyjar(self)

        for id, keys in trust_anchors.items():
            keyjar.import_jwks(keys, id)

        self.config_cache = {}
        self.entity_statement_cache = {}

    def collect_tree(self,
                     entity_id: str,
                     entity_configuration: dict,
                     seen: Optional[list] = None,
                     max_superiors: Optional[int] = 1,
                     stop_at: Optional[str] = ""
                     ):
        superior = {}
        if seen is None:
            seen = []

        try:
            _hints = entity_configuration['authority_hints']
        except KeyError:
            pass
        else:
            if entity_configuration['iss'] == stop_at:
                pass
            else:
                for authority in _hints:
                    superior[authority] = self.collect_branch(entity_id, authority, seen,
                                                              max_superiors, stop_at)

        return superior

    def get_entity_configuration(self, subject_id):
        """

        :param subject_id:
        :return: A signed JWT
        """
        es_api = FSFetchEntityStatement(self.root_dir, iss=get_netloc(subject_id))
        jws = es_api.create_entity_statement(get_netloc(subject_id))
        self.config_cache[subject_id] = jws
        return jws

    def get_entity_statement(self, fetch_endpoint, issuer, subject):
        es_api = FSFetchEntityStatement(self.root_dir, iss=get_netloc(issuer))
        _jws = es_api.create_entity_statement(get_netloc(subject))
        _cache_key = cache_key(issuer, subject)
        self.entity_statement_cache[_cache_key] = _jws
        return _jws

    def collect_branch(self, entity_id, authority, seen=None, max_superiors=10, stop_at=""):
        """
        Builds a trust path as a sequence of signed JWTs containing entity
        statements

        :param authority: Which issuer to use
        :param entity_id: The identifier of the subject
        :return: An Issuer instance
        """
        if authority not in self.config_cache:
            _jws = self.get_entity_configuration(authority)
            self.config_cache[authority] = unverified_entity_statement(_jws)

        jws = self.get_entity_statement('', issuer=authority, subject=entity_id)

        if jws:
            _entity_configuration = self.config_cache[authority]
            return jws, self.collect_tree(authority,
                                          _entity_configuration,
                                          stop_at=stop_at,
                                          seen=seen,
                                          max_superiors=max_superiors)
        else:
            return None

    def __call__(self,
                 entity_id: str,
                 max_superiors: Optional[int] = 10,
                 seen: Optional[List[str]] = None,
                 stop_at: Optional[str] = ''):
        # get leaf Entity Configuration
        signed_entity_config = self.get_entity_configuration(entity_id)
        entity_config = verify_self_signed_signature(signed_entity_config)
        #
        entity_config['_jws'] = signed_entity_config

        return self.collect_tree(entity_id, entity_config, seen=seen, max_superiors=max_superiors,
                                 stop_at=stop_at), signed_entity_config

    def add_trust_anchor(self, entity_id, jwks):
        if self.keyjar:
            _keyjar = self.keyjar
        elif self.upstream_get:
            _keyjar = get_federation_entity_keyjar(self)
        else:
            raise ValueError("Missing keyjar")

        _keyjar.import_jwks(jwks, entity_id)
        self.trust_anchors[entity_id] = jwks

    def get_chain(self, iss_path, trust_anchor, with_ta_ec: Optional[bool] = False):
        # Entity configuration for the leaf
        res = [self.config_cache[iss_path[0]]['_jws']]
        # Entity statements up the chain
        for i in range(len(iss_path) - 1):
            res.append(self.entity_statement_cache[cache_key(iss_path[i + 1], iss_path[i])])
        # Possibly add Trust Anchor entity configuration
        if with_ta_ec:
            res.append(self.config_cache[trust_anchor]['_jws'])
        return res




