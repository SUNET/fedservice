import logging
from ssl import SSLError
import sys
import time
import traceback
from typing import Callable
from typing import List
from typing import Optional
from typing import Union

from cryptojwt import JWT
from cryptojwt import KeyJar
from cryptojwt.jws.jws import factory
from cryptojwt.jwt import utc_time_sans_frac
from idpyoidc.exception import MissingPage
from idpyoidc.key_import import import_jwks
from idpyoidc.message import Message
from requests.exceptions import ConnectionError

from fedservice.defaults import DEFAULT_SIGNING_ALGORITHM
from fedservice.entity.function import Function
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import verify_trust_chains
from fedservice.entity.utils import get_federation_entity
from fedservice.entity_statement.cache import ESCache
from fedservice.exception import FailedConfigurationRetrieval
from fedservice.utils import statement_is_expired

logger = logging.getLogger(__name__)


def unverified_entity_statement(signed_jwt):
    _jws = factory(signed_jwt)
    if not _jws:
        raise ValueError(f"Not a proper signed JWT: {signed_jwt}")
    return _jws.jwt.payload()


def signing_algorithm(signed_jwt):
    _jws = factory(signed_jwt)
    return _jws.jwt.headers.get("alg", DEFAULT_SIGNING_ALGORITHM)


def verify_self_signed_signature(statement):
    """
    Verify signature using only keys in the entity statement.
    Will raise exception if signature verification fails.

    :param statement: Signed JWT
    :return: Payload of the signed JWT
    """

    payload = unverified_entity_statement(statement)
    keyjar = KeyJar()
    if payload['iss'] not in keyjar:
        keyjar = import_jwks(keyjar, payload['jwks'], payload['iss'])

    _jwt = JWT(key_jar=keyjar, sign_alg=signing_algorithm(statement))
    _val = _jwt.unpack(statement)
    return _val


def get_endpoint(endpoint_type, config):
    _fe = config['metadata']['federation_entity']
    return _fe.get(f"federation_{endpoint_type}_endpoint")


def cache_key(authority, entity):
    return f"{authority}!!{entity}"


def time_key(authority, entity):
    return f"{authority}!exp!{entity}"


class TrustChainCollector(Function):

    def __init__(self,
                 upstream_get: Callable,
                 trust_anchors: dict,
                 allowed_delta: int = 300,
                 keyjar: Optional[KeyJar] = None,
                 **kwargs
                 ):
        Function.__init__(self, upstream_get)
        self.trust_anchors = trust_anchors
        self.allowed_delta = allowed_delta
        self.config_cache = ESCache(allowed_delta=allowed_delta)
        self.entity_statement_cache = ESCache(allowed_delta=allowed_delta)
        # should not have a Key Jar of its own
        if keyjar:
            self.keyjar = keyjar
        else:
            self.keyjar = None
            keyjar = upstream_get("attribute", "keyjar")
        for id, keys in trust_anchors.items():
            keyjar = import_jwks(keyjar, keys, id)

    def _get_service(self, service):
        federation_entity = get_federation_entity(self)
        return federation_entity.client.get_service(service)

    def get_document(self, url: str):
        """

        :param url: Target URL
        :param httpc_args: Arguments for the HTTP call.
        :return: Signed EntityConfiguration or SubordinateStatement
        """
        _keyjar = self.upstream_get('attribute', 'keyjar')

        _httpc_params = _keyjar.httpc_params
        logger.debug(f"keyjar.httpc_params: {_httpc_params}")
        if not _httpc_params:
            federation_entity = get_federation_entity(self)
            _httpc_params = federation_entity.httpc_params
            logger.debug(f"federation_entity.httpc_params: {_httpc_params}")

        logger.debug(f"Using HTTPC Params: {_httpc_params}")
        try:
            response = self.upstream_get('attribute', 'httpc')("GET", url, **_httpc_params)
        except ConnectionError as err:
            logger.error(f'Could not connect to {url}:{err}')
            raise

        if response.status_code == 200:
            if 'application/entity-statement+jwt' not in response.headers['Content-Type']:
                logger.warning(f"Wrong Content-Type: {response.headers['Content-Type']}")
            return response.text
        elif response.status_code == 404:
            raise MissingPage(f"No such page: '{url}'")
        else:
            logger.error(f"status_code: {response.status_code} on get {url}")
            if response.text:
                logger.info(f"Error description: {response.text}")
            raise FailedConfigurationRetrieval()

    def get_entity_configuration(self, entity_id):
        """
        Get configuration information about an entity from itself.
        The configuration information is in the format of an Entity Statement

        :param entity_id: About whom the entity statement should be
        :return: Configuration information as a signed JWT
        """
        logger.debug(f"--get_configuration_information({entity_id})")
        _serv = self._get_service('entity_configuration')
        _res = _serv.get_request_parameters(request_args={"entity_id": entity_id})
        logger.debug(f"Get configuration from: {_res['url']}")
        try:
            # if self.use_ssc:
            #     logger.debug("Use SelfSignedCert support")
            #     self_signed_config = self.do_ssc_seq(_url, entity_id)
            # else:
            self_signed_config = self.get_document(_res['url'])
        except MissingPage:  # if tenant involved
            _tres = _serv.get_request_parameters(request_args={"entity_id": entity_id}, tenant=True)
            logger.debug(f"Get configuration from (tenant): '{entity_id}'")
            if _tres["url"] != _res["url"]:
                # if self.use_ssc:
                #     self_signed_config = self.do_ssc_seq(_tenant_url, entity_id)
                # else:
                self_signed_config = self.get_document(_tres["url"])
                logger.debug(f'Self signed statement: {self_signed_config}')
            else:
                raise MissingPage(f"No such page: '{_tres['url']}'")
        except SSLError as err:
            logger.error(err)
            raise
        except ConnectionError as err:
            logger.error(err)
            raise
        except Exception as err:
            logger.exception(err)
            raise

        return self_signed_config

    def get_metadata(self, entity_id):
        _ec = None
        if entity_id in self.config_cache:
            _ec = self.config_cache[entity_id]
            if statement_is_expired(_ec):
                _ec = None

        if _ec is None:
            _collection = self.upstream_get('unit')
            _federation_entity = _collection.upstream_get('unit')
            _chains, _ = collect_trust_chains(_federation_entity, entity_id)
            _trust_chains = verify_trust_chains(_federation_entity, _chains)
            _ec = self.config_cache[entity_id]

        return _ec['metadata']

    def get_verified_self_signed_entity_configuration(self, entity_id: str) -> str:
        signed_entity_config = self.get_entity_configuration(entity_id)
        if signed_entity_config is None:
            return ''

        return verify_self_signed_signature(signed_entity_config)

    def get_federation_fetch_endpoint(self, intermediate: str) -> str:
        logger.debug(f'--get_federation_fetch_endpoint({intermediate})')
        # In cache ??
        _entity_config = self.config_cache[intermediate]
        if _entity_config:
            logger.debug(f'Cached info: {_entity_config}')
            # will return None if cached information is outdated
            fed_fetch_endpoint = get_endpoint("fetch", _entity_config)
        else:
            fed_fetch_endpoint = None

        if not fed_fetch_endpoint:
            signed_entity_config = self.get_entity_configuration(intermediate)
            if signed_entity_config is None:
                return ''

            entity_config = verify_self_signed_signature(signed_entity_config)
            logger.debug(f'Verified self signed statement: {entity_config}')
            fed_fetch_endpoint = get_endpoint("fetch", entity_config)
            # update cache
            entity_config["_jws"] = signed_entity_config
            self.config_cache[intermediate] = entity_config

        return fed_fetch_endpoint

    def get_entity_statement(self, fetch_endpoint, issuer, subject):
        """
        Get Entity Statement by one entity about another or about itself

        :param fetch_endpoint: The federation fetch endpoint
        :param issuer: Who should issue the entity statement
        :param subject: About whom the entity statement should be
        :return: A signed JWT
        """
        _serv = self._get_service('entity_statement')
        _res = _serv.get_request_parameters(subject=subject, fetch_endpoint=fetch_endpoint)

        # if self.use_ssc:
        #     signed_entity_statement = self.do_ssc_seq(_url, issuer)
        # else:
        try:
            return self.get_document(_res['url'])
        except FailedConfigurationRetrieval:
            logger.error(f"Failed to fetch {_res['url']}")
            logger.error(f"Request: {_res}")
            raise

    def collect_tree(self,
                     entity_id: str,
                     entity_configuration: Union[dict, Message],
                     seen: Optional[list] = None,
                     max_superiors: Optional[int] = 1,
                     stop_at: Optional[str] = "") -> Optional[dict]:
        """
        Collect superiors one level at the time

        :param entity_id: The entity ID
        :param entity_configuration: Entity Configuration as a dictionary
        :param seen: A list of authorities that this process has seen. This to capture
            loops. Also used to control the allowed depth.
        :param max_superiors: The maximum number of superiors.
        :param stop_at: The ID of the trust anchor at which the trust chain should stop.
        :return: Dictionary of superiors
        """
        superior = {}
        if seen is None:
            seen = []

        logger.debug(f'Collect superiors to: {entity_id}')
        logger.debug(f'Collect based on: {entity_configuration}')
        if 'authority_hints' not in entity_configuration:
            logger.debug("No authority for this entity")
            return superior
        elif entity_configuration['iss'] == stop_at:
            logger.debug("Reached stop point")
            return superior

        logger.debug(f"Authority_hints: {entity_configuration['authority_hints']}")
        for authority in entity_configuration['authority_hints']:
            logger.info(f"authority: {authority}")
            if authority in seen:  # loop ?!
                logger.warning(f"Loop detected at {authority}")
                continue
            try:
                superior[authority] = self.collect_branch(entity_id, authority, seen,
                                                          max_superiors, stop_at=stop_at)
            except Exception as err:
                message = traceback.format_exception(*sys.exc_info())
                logger.error(message)
                continue

        return superior

    def _get_entity_statement(self, entity: str, authority: str) -> Optional[str]:
        # Try to get the entity statement from the cache
        _cache_key = cache_key(authority, entity)
        entity_statement = self.entity_statement_cache[_cache_key]

        if entity_statement is not None:
            logger.debug("Have cached statement")
            # Verify that the cached statement is not too old
            _now = utc_time_sans_frac()
            _time_key = time_key(authority, entity)
            _exp = self.entity_statement_cache[_time_key]
            if _now > (_exp - self.allowed_delta):
                logger.debug("Cached entity statement timed out")
                del self.entity_statement_cache[_cache_key]
                del self.entity_statement_cache[_time_key]
                entity_statement = None

        if entity_statement is None:
            logger.debug(f"Have not seen '{authority}' before")
            # The entity configuration for authority is collected at this point
            # It's stored in config_cache
            fed_fetch_endpoint = self.get_federation_fetch_endpoint(authority)
            if not fed_fetch_endpoint:
                return None
            logger.debug(f"Federation fetch endpoint: '{fed_fetch_endpoint}' for '{authority}'")
            entity_statement = self.get_entity_statement(fed_fetch_endpoint, authority, entity)
            # entity_statement is a signed JWT
            statement = unverified_entity_statement(entity_statement)
            logger.debug(
                f"Unverified entity statement from {fed_fetch_endpoint} about {entity}: "
                f"{statement}")
            self.entity_statement_cache[_cache_key] = entity_statement
            self.entity_statement_cache[time_key(authority, entity)] = statement["exp"]

        return entity_statement

    def collect_branch(self, entity, authority, seen=None, max_superiors=10, stop_at=""):
        """
        Collect an entity statement about an entity submitted by another entity, the authority.
        This consist of first finding the fed_fetch_endpoint URL for the authority and then
        asking the authority for its view of the entity.

        :param authority: An authority from the authority_hints
        :param stop_at: When this entity ID is reached stop processing
        :param entity: The ID of the entity
        :param seen: A list of authorities that this process has seen. This to capture
            loops. Also used to control the allowed depth.
        :param max_superiors: The maximum number of superiors allowed.
        :return:
        """

        logger.debug(f'Get view of "{entity}" from "{authority}"')
        # Should I stop when I reach the first trust anchor ?
        if entity == authority and entity in self.trust_anchors:
            return None

        if seen is None:
            _seen = []
        else:
            _seen = seen[:]

        _seen.append(authority)
        # if len(_seen) > max_superiors:
        #     logger.warning("Reached max superiors. The path here was {}".format(_seen))
        #     return None

        entity_statement = self._get_entity_statement(entity, authority)

        if entity_statement:
            _entity_configuration = self.config_cache[authority]
            return entity_statement, self.collect_tree(authority,
                                                       _entity_configuration,
                                                       stop_at=stop_at,
                                                       seen=_seen,
                                                       max_superiors=max_superiors)
        else:
            return None

    def too_old(self, statement):
        now = time.time()
        if now >= statement["exp"] + self.allowed_delta:
            return True
        else:
            return False

    def __call__(self,
                 entity_id: str,
                 max_superiors: Optional[int] = 10,
                 seen: Optional[List[str]] = None,
                 stop_at: Optional[str] = ''):
        entity_config = self.config_cache.get(entity_id, None)
        if entity_config and not self.too_old(entity_config):
            signed_entity_config = entity_config.get("_jws")
            if not signed_entity_config:
                signed_entity_config = getattr(entity_config, "_jws")
        else:
            signed_entity_config = None

        if not signed_entity_config:
            # get leaf Entity Configuration
            signed_entity_config = self.get_entity_configuration(entity_id)
            if not signed_entity_config:
                logger.warning(f"Could not find any entity configuration for {entity_id}")
                return None
            entity_config = verify_self_signed_signature(signed_entity_config)
            logger.debug(f'Verified self signed statement: {entity_config}')
            entity_config['_jws'] = signed_entity_config
            # update cache
            self.config_cache[entity_id] = entity_config

        return self.collect_tree(entity_id, entity_config, seen=seen, max_superiors=max_superiors,
                                 stop_at=stop_at), signed_entity_config

    def add_trust_anchor(self, entity_id, jwks):
        if self.keyjar:
            _keyjar = self.keyjar
        elif self.upstream_get:
            _keyjar = self.upstream_get('attribute', 'keyjar')
        else:
            raise ValueError("Missing keyjar")

        _keyjar = import_jwks(_keyjar, jwks, entity_id)
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
