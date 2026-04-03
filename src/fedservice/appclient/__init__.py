import logging
import re
from json import JSONDecodeError
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from cryptojwt.key_jar import init_key_jar
from idpyoidc.client.client_auth import client_auth_setup
from idpyoidc.client.client_auth import method_to_item
from idpyoidc.client.defaults import SUCCESSFUL
from idpyoidc.client.exception import OidcServiceError
from idpyoidc.client.rp_handler import RPHandler
from idpyoidc.client.service import init_services
from idpyoidc.client.service import REQUEST_INFO
from idpyoidc.client.service import Service
from idpyoidc.client.service_context import ServiceContext
from idpyoidc.client.util import do_add_ons
from idpyoidc.client.util import get_deserialization_method
from idpyoidc.configure import Configuration
from idpyoidc.context import OidcContext
from idpyoidc.exception import FormatError
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.node import ClientUnit

from fedservice.defaults import COMBINED_DEFAULT_OAUTH2_SERVICES
from fedservice.defaults import COMBINED_DEFAULT_OIDC_SERVICES
from fedservice.defaults import DEFAULT_REGISTRATION_TYPE
from fedservice.message import OauthClientMetadata
from fedservice.message import OIDCRPMetadata

logger = logging.getLogger(__name__)

ENTITY2CLIENT_TYPE = {
    "openid_relying_party": "oidc",
    "oauth_client": "oauth2"
}


class ClientEntity(ClientUnit):
    name = 'openid_relying_party'

    def __init__(
            self,
            upstream_get: Optional[Callable] = None,
            entity_id: Optional[str] = '',
            httpc: Optional[Callable] = None,
            keyjar: Optional[KeyJar] = None,
            config: Optional[Union[dict, Configuration]] = None,
            services: Optional[dict] = None,
            jwks_uri: Optional[str] = "",
            httpc_params: Optional[dict] = None,
            context: Optional[OidcContext] = None,
            key_conf: Optional[dict] = None,
            client_type: Optional[str] = '',
            entity_type: Optional[str] = ''
    ):
        if config is None:
            config = {}

        self.client_type = config.get('client_type', client_type)
        self.entity_type = config.get("entity_type", entity_type)
        if not self.client_type:
            self.client_type = ENTITY2CLIENT_TYPE.get(self.entity_type, "")
            if not self.client_type:
                self.client_type = ENTITY2CLIENT_TYPE[self.name]

        self.entity_id = entity_id or config.get("entity_id", config.get("client_id", ""))

        if self.client_type == "oauth2":
            self.metadata_class = OauthClientMetadata
        else:
            self.metadata_class = OIDCRPMetadata

        self.metadata = {}

        ClientUnit.__init__(self, upstream_get=upstream_get, keyjar=keyjar, httpc=httpc,
                            httpc_params=httpc_params, context=context, config=config,
                            entity_id=entity_id, key_conf=key_conf)

        if 'metadata' in config:
            config.update(config['metadata'])
            del config['metadata']

        _srvs = services or config.get("services")

        if not _srvs:
            if self.client_type == "oidc":
                _srvs = COMBINED_DEFAULT_OIDC_SERVICES
            elif client_type == "oauth2":
                _srvs = COMBINED_DEFAULT_OAUTH2_SERVICES

        self._service = init_services(service_definitions=_srvs, upstream_get=self.unit_get)

        if context:
            self.context = context
        else:
            if key_conf:
                config['key_conf'] = key_conf
            self.context = ServiceContext(
                config=config, jwks_uri=jwks_uri, key_conf=key_conf, upstream_get=self.unit_get,
                keyjar=self.keyjar, metadata_class=self.metadata_class,
                client_type=self.client_type,
                entity_id=self.entity_id
            )

        self.setup_client_authn_methods(config)

        if "add_ons" in config:
            do_add_ons(config["add_ons"], self._service)

        # What's the default ? explicit/automatic ? automatic for the time being.
        _preference = config.get("preference")
        if _preference:
            registration_types = _preference.get("client_registration_types", [DEFAULT_REGISTRATION_TYPE])
        else:
            registration_types = [DEFAULT_REGISTRATION_TYPE]

        if "automatic" not in registration_types:
            authz_service = self._service.get("authorization")
            # Is it safe to assume it's the last item ?
            # authz_service.pre_construct.pop()
            try:
                authz_service.pre_construct.remove(authz_service._automatic_registration)
            except AttributeError:
                pass

    def setup_client_authn_methods(self, config):
        if config and "client_authn_methods" in config:
            _methods = config.get("client_authn_methods")
            self.context.client_authn_methods = client_auth_setup(method_to_item(_methods))
        else:
            self.context.client_authn_methods = {}

    def get_services(self, *arg):
        return self._service

    def get_context(self, *arg):
        return self.context

    def get_service(self, service_name, *arg):
        try:
            return self._service[service_name]
        except KeyError:
            return None

    def get_service_by_endpoint_name(self, endpoint_name, *arg):
        for service in self._service.values():
            if service.endpoint_name == endpoint_name:
                return service

        return None

    def get_entity(self):
        return self

    def get_client_id(self):
        return self.entity_id

    def get_metadata(self, entity_type="", *args):
        logger.debug(f"{self.name}:get_metadata")
        if not entity_type:
            if self.client_type == "oauth2":
                entity_type = "oauth_client"
            elif self.client_type == "oidc":
                entity_type = "openid_relying_party"

        res = self.context.claims.get_client_metadata(entity_type=entity_type,
                                                      metadata_schema=self.metadata_class)
        logger.debug(f"metadata:{entity_type} = {res}")
        return res

    def get_registration_metadata(self, entity_type="", *args):
        if not entity_type:
            if self.client_type == "oauth2":
                entity_type = "oauth_client"
            elif self.client_type == "oidc":
                entity_type = "openid_relying_party"

        return self.context.claims.get_registration_metadata(entity_type=entity_type,
                                                             metadata_schema=self.metadata_class)

    def do_request(
            self,
            request_type: str,
            response_body_type: Optional[str] = "",
            request_args: Optional[dict] = None,
            behaviour_args: Optional[dict] = None,
            **kwargs
    ):
        _srv = self._service[request_type]

        _info = _srv.get_request_parameters(request_args=request_args, **kwargs)

        if not response_body_type:
            response_body_type = _srv.response_body_type

        logger.debug(f"do_request info: {_info}")

        try:
            _state = kwargs["state"]
        except:
            _state = ""
        return self.service_request(
            _srv, response_body_type=response_body_type, state=_state, **_info
        )

    def set_client_id(self, client_id):
        self.context.set("client_id", client_id)

    def get_response(
            self,
            service: Service,
            url: str,
            method: Optional[str] = "GET",
            body: Optional[dict] = None,
            response_body_type: Optional[str] = "",
            headers: Optional[dict] = None,
            **kwargs
    ):
        """

        :param url:
        :param method:
        :param body:
        :param response_body_type:
        :param headers:
        :param kwargs:
        :return:
        """
        try:
            resp = self.httpc(method, url, data=body, headers=headers, **self.httpc_params)
        except Exception as err:
            logger.error(f"Exception on request: {err}")
            raise

        if 300 <= resp.status_code < 400:
            return {"http_response": resp}

        if resp.status_code < 300:
            if "keyjar" not in kwargs:
                kwargs["keyjar"] = service.upstream_get("attribute", 'keyjar')
            if not response_body_type:
                response_body_type = service.response_body_type

            if response_body_type == "html":
                return resp.text

            if body:
                kwargs["request_body"] = body

        return self.parse_request_response(service, resp, response_body_type, **kwargs)

    def service_request(
            self,
            service: Service,
            url: str,
            method: Optional[str] = "GET",
            body: Optional[dict] = None,
            response_body_type: Optional[str] = "",
            headers: Optional[dict] = None,
            **kwargs
    ) -> Message:
        """
        The method that sends the request and handles the response returned.
        This assumes that the response arrives in the HTTP response.

        :param service: The Service instance
        :param url: The URL to which the request should be sent
        :param method: Which HTTP method to use
        :param body: A message body if any
        :param response_body_type: The expected format of the body of the
            return message
        :param httpc_params: Arguments for the HTTP client
        :return: A cls or ResponseMessage instance or the HTTP response
            instance if no response body was expected.
        """

        if headers is None:
            headers = {}

        logger.debug(REQUEST_INFO.format(url, method, body, headers))

        # returns list of trust chains
        response = self.get_response(
            service, url, method, body, response_body_type, headers, **kwargs
        )

        if "error" in response:
            pass
        else:
            try:
                kwargs["key"] = kwargs["state"]
            except KeyError:
                pass

            service.update_service_context(response, **kwargs)
        return response

    def _parse_unsigned_reponse(self, response, deser_method):
        if deser_method == 'json':
            err_resp = ResponseMessage().from_json(response).to_dict()
        elif deser_method == "urlencoded":
            err_resp = ResponseMessage().from_urlencoded(response).to_dict()
        else:
            err_resp = {"error": response}

        return err_resp

    def _parse_signed_response(self, service, response, deser_method, state, **kwargs):
        return service.parse_response(response, deser_method, state, **kwargs)

    def _parse_response(self, service, response, body_type, state, **kwargs):
        try:
            return self._parse_signed_response(service, response, body_type, state, **kwargs)
        except Exception:
            _resp = self._parse_unsigned_reponse(response, body_type)
            logger.warning('Unsigned response')
            return _resp

    def parse_request_response(self, service, reqresp, response_body_type="", state="", **kwargs):
        """
        Deal with a self.http response. The response are expected to
        follow a special pattern, having the attributes:

            - headers (list of tuples with headers attributes and their values)
            - status_code (integer)
            - text (The text version of the response)
            - url (The calling URL)

        :param service: A :py:class:`idpyoidc.client.service.Service` instance
        :param reqresp: The HTTP request response
        :param response_body_type: If response in body one of 'json', 'jwt' or
            'urlencoded'
        :param state: Session identifier
        :param kwargs: Extra keyword arguments
        :return:
        """

        # if not response_body_type:
        #     response_body_type = self.response_body_type

        if reqresp.status_code in SUCCESSFUL:
            logger.debug(f'response_body_type: "{response_body_type}"')
            content_type = reqresp.headers.get("content-type")
            _deser_method = get_deserialization_method(content_type)

            if content_type != response_body_type:
                logger.warning(f"Not the body type I expected: {content_type} != {response_body_type}")
            if _deser_method in ["json", "jwt", "urlencoded"]:
                body_type = _deser_method
            else:
                body_type = response_body_type

            logger.debug(f"Successful response: {reqresp.text}")

            try:
                return self._parse_signed_response(service, reqresp.text, body_type, state,
                                                   **kwargs)
            except Exception as err:
                logger.error(err)
                raise
        elif reqresp.status_code in [302, 303]:  # redirect
            return reqresp
        elif reqresp.status_code == 500:
            logger.error("(%d) %s" % (reqresp.status_code, reqresp.text))
            raise SystemError(f"ERROR: Something went wrong: {reqresp.text}")
        elif 400 <= reqresp.status_code < 500:
            logger.error(f"Error response ({reqresp.status_code}): {reqresp.text}")
            # expecting an error response
            content_type = reqresp.headers.get("content-type")
            _deser_method = get_deserialization_method(content_type)
            if not content_type:
                content_type = "application/json"

            try:
                err_resp = self._parse_response(service, reqresp.text, content_type, state,
                                                **kwargs)
            except (FormatError, ValueError):
                if content_type != response_body_type:
                    logger.warning(f'Response with wrong content-type: {content_type}')
                    try:
                        err_resp = self._parse_response(service,
                                                        response=reqresp.text,
                                                        body_type=response_body_type,
                                                        state=state,
                                                        **kwargs)
                    except (OidcServiceError, FormatError, ValueError):
                        raise OidcServiceError(
                            "HTTP ERROR: %s [%s] on %s"
                            % (reqresp.text, reqresp.status_code, reqresp.url)
                        )
                else:
                    raise OidcServiceError(
                        "HTTP ERROR: %s [%s] on %s"
                        % (reqresp.text, reqresp.status_code, reqresp.url)
                    )
            except JSONDecodeError:  # So it's not JSON assume text then
                err_resp = {"error": reqresp.text}

            err_resp["status_code"] = reqresp.status_code
            return err_resp
        else:
            logger.error(f"Error response ({reqresp.status_code}): {reqresp.text}")
            raise OidcServiceError(
                f"HTTP ERROR: {reqresp.text} [{reqresp.status_code}] on {reqresp.url}")


def init_oidc_rp_handler(app, dir: Optional[str] = ""):
    _rp_conf = app.rp_config

    if _rp_conf.key_conf:
        _kj = init_key_jar(**_rp_conf.key_conf)
        _path = _rp_conf.key_conf['public_path']
        # removes ./ and / from the beginning of the string
        _path = re.sub('^(.)/', '', _path)
    else:
        _kj = KeyJar()
        _path = ''
    _kj.httpc_params = _rp_conf.httpc_params

    rph = RPHandler(base_url=dir,
                    client_configs=_rp_conf.clients,
                    services=_rp_conf.services,
                    keyjar=_kj,
                    hash_seed=_rp_conf.hash_seed,
                    httpc_params=_rp_conf.httpc_params,
                    jwks_path=_path,
                    )

    return rph

#
# class RPHandler(rp_handler.RPHandler):
#
#     def __init__(self,
#                  base_url: Optional[str] = '',
#                  hash_seed: Optional[str] = "",
#                  keyjar: Optional[KeyJar] = None,
#                  verify_ssl: Optional[bool] = True,
#                  services: Optional[dict] = None,
#                  service_factory=None,
#                  client_configs: Optional[Union[Configuration, dict]] = None,
#                  client_cls: Optional[Any] = None,
#                  state_db: Optional[Any] = None,
#                  federation_entity_config: Optional[Union[Configuration, dict]] = None,
#                  httpc_params: Optional[dict] = None,
#                  upstream_get: Optional[Callable] = None,
#                  **kwargs):
#         rp_handler.RPHandler.__init__(self, base_url=base_url, hash_seed=hash_seed, keyjar=keyjar,
#                                       verify_ssl=verify_ssl, services=services,
#                                       service_factory=service_factory,
#                                       client_configs=client_configs,
#                                       client_cls=client_cls,
#                                       state_db=state_db, httpc_params=httpc_params, **kwargs)
#
#         self.federation_entity_config = federation_entity_config
#         self.upstream_get = upstream_get
#
#     def init_client(self, issuer):
#         client = rp_handler.RPHandler.init_client(self, issuer)
#         client.upstream_get = self.upstream_get
#         # client.upstream_get("context").federation_entity = self.init_federation_entity(
#         #     issuer,
#         #     host=client)
#         # client.set_client_id(
#         #     client.upstream_get("context").federation_entity.context.entity_id)
#         return client
#
#     def init_federation_entity(self, issuer, host):
#         args = {k: v for k, v in self.federation_entity_config["conf"].items()}
#
#         # _cnf = self.client_configs.get(issuer).get("federation")
#         # args.update(_cnf)
#
#         _entity_id = args.get('entity_id', '')
#         if not _entity_id:
#             args['entity_id'] = self.federation_entity_config['entity_id']
#
#         logger.debug('Entity ID: %s', _entity_id)
#
#         _federation_entity = create_federation_entity(httpc_params=self.httpc_params,
#                                                       issuer=issuer, **args)
#
#         _federation_entity.host = host
#         _federation_entity.context.keyjar.httpc_params = self.httpc_params
#         _federation_entity.collector.web_cert_path = self.federation_entity_config.get(
#             'web_cert_path')
#         return _federation_entity
#
#     def client_setup(self,
#                      iss_id: Optional[str] = '',
#                      user: Optional[str] = '',
#                      behaviour_args: Optional[dict] = None) -> Client:
#         """
#         First if no issuer ID is given then the identifier for the user is
#         used by the webfinger service to try to find the issuer ID.
#         Once the method has an issuer ID if no client is bound to this issuer
#         one is created and initiated with
#         the necessary information for the client to be able to communicate
#         with the OP/AS that has the provided issuer ID.
#
#         :param iss_id: The issuer ID
#         :param user: A user identifier
#         :return: A :py:class:`idpyoidc.client.oidc.Client` instance
#         """
#
#         logger.info(f'client_setup: iss_id={iss_id}, user={user}')
#
#         if not iss_id:
#             if not user:
#                 raise ValueError('Need issuer or user')
#
#             logger.debug("Connecting to previously unknown OP")
#             temporary_client = self.init_client('')
#             temporary_client.do_request('webfinger', resource=user)
#         else:
#             temporary_client = None
#
#         try:
#             client = self.issuer2rp[iss_id]
#         except KeyError:
#             if temporary_client:
#                 client = temporary_client
#             else:
#                 logger.debug("Creating new client: %s", iss_id)
#                 client = self.init_client(iss_id)
#         else:
#             return client
#
#         logger.debug("Get provider info")
#         issuer = self.do_provider_info(client, behaviour_args=behaviour_args)
#         _sc = client.upstream_get("context")
#         try:
#             _fe = _sc.federation_entity
#         except AttributeError:
#             _fe = None
#             registration_type = 'explicit'
#         else:
#             registration_type = _fe.context.registration_type
#
#         # if client.mint_redirect_uris():
#         #     self.hash2issuer[iss_id] = issuer
#
#         if registration_type != 'automatic':  # explicit
#             logger.debug("Do client registration")
#             self.do_client_registration(client, iss_id, behaviour_args=behaviour_args)
#
#         self.issuer2rp[issuer] = client
#         return client
#
#
# def init_oidc_rp_handler(config, dir_path):
#     rp_keys_conf = config.key_conf
#     _fed_conf = config.federation
#
#     _httpc_params = config.httpc_params
#
#     _path = rp_keys_conf['uri_path']
#     if _path.startswith('./'):
#         _path = _path[2:]
#     elif _path.startswith('/'):
#         _path = _path[1:]
#
#     args = {k: v for k, v in rp_keys_conf.items() if k != "uri_path"}
#     rp_keyjar = init_key_jar(**args)
#     rp_keyjar.httpc_params = _httpc_params
#
#     rph = RPHandler(base_url=config.base_url, hash_seed=config.hash_seed,
#                     jwks_path=_path, client_configs=config.clients, keyjar=rp_keyjar,
#                     services=config.services, httpc_params=_httpc_params,
#                     federation_entity_config=_fed_conf, client_cls=FederationRP)
#
#     return rph
