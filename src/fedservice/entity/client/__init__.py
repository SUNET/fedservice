import logging
from json import JSONDecodeError
from typing import Callable
from typing import List
from typing import Optional
from typing import Union

from cryptojwt.key_jar import KeyJar
from idpyoidc.client.client_auth import client_auth_setup
from idpyoidc.client.configure import Configuration
from idpyoidc.client.defaults import SUCCESSFUL
from idpyoidc.client.exception import OidcServiceError
from idpyoidc.client.service import init_services
from idpyoidc.client.service import REQUEST_INFO
from idpyoidc.client.service import Service
from idpyoidc.client.service_context import CLI_REG_MAP
from idpyoidc.client.service_context import PROVIDER_INFO_MAP
from idpyoidc.client.util import do_add_ons
from idpyoidc.client.util import get_content_type
from idpyoidc.client.util import get_deserialization_method
from idpyoidc.exception import FormatError
from idpyoidc.exception import ParseError
from idpyoidc.key_import import import_jwks
from idpyoidc.message import Message
from idpyoidc.node import ClientUnit
from requests import request

from fedservice.defaults import DEFAULT_FEDERATION_ENTITY_SERVICES
from fedservice.entity import FederationContext

logger = logging.getLogger(__name__)


class FederationServiceContext(FederationContext):

    def __init__(self,
                 config: Optional[Union[dict, Configuration]] = None,
                 entity_id: str = "",
                 upstream_get: Callable = None,
                 keyjar: Optional[KeyJar] = None,
                 priority: Optional[List[str]] = None,
                 trust_marks: Optional[List[str]] = None,
                 trust_mark_issuers: Optional[dict] = None,
                 trust_mark_owners: Optional[dict] = None,
                 trusted_roots: Optional[dict] = None,
                 metadata: Optional[dict] = None,
                 ):

        if config is None:
            config = {}

        FederationContext.__init__(self,
                                   config=config,
                                   entity_id=entity_id,
                                   upstream_get=upstream_get,
                                   keyjar=keyjar,
                                   metadata=metadata,
                                   trust_marks=trust_marks,
                                   trust_mark_issuers=trust_mark_issuers,
                                   trust_mark_owners=trust_mark_owners,
                                   tr_priority=priority
                                   )

        self.trust_mark_issuer = None
        self.signed_trust_marks = []
        _key_jar = self.upstream_get("attribute", "keyjar")
        for iss, jwks in self.trusted_roots.items():
            _key_jar = import_jwks(_key_jar, jwks, iss)
        self.server_metadata = {}

    def _get_crypt(self, typ, attr):
        _item_typ = CLI_REG_MAP.get(typ)
        _alg = ''
        if _item_typ:
            _alg = self.claims.get_usage(_item_typ[attr])
            if not _alg:
                _alg = self.claims.get_preference(_item_typ[attr])

        _provider_info = {}
        if not _alg and _provider_info:
            _item_typ = PROVIDER_INFO_MAP.get(typ)
            if _item_typ:
                _alg = _provider_info.get(_item_typ[attr])

        return _alg

    def get_sign_alg(self, typ):
        """

        :param typ: ['id_token', 'userinfo', 'request_object']
        :return: signing algorithm
        """
        return self._get_crypt(typ, 'sign')

    def get_enc_alg_enc(self, typ):
        """

        :param typ:
        :return:
        """

        res = {}
        for attr in ["enc", "alg"]:
            res[attr] = self._get_crypt(typ, attr)

        return res

    def get_keyjar(self):
        val = getattr(self, 'keyjar', None)
        if not val:
            return self.upstream_get('attribute', 'keyjar')
        else:
            return val

    def get_client_id(self):
        return self.claims.get_usage("client_id")

    def get_metadata_claim(self, claim, entity_type: Optional[List[str]] = ""):
        if entity_type:
            for _type in entity_type:
                if _type in self.server_metadata:
                    _val = self.server_metadata[_type].get(claim)
                    if _val:
                        return _val
            raise KeyError(f"{claim} not in {entity_type} metadata")
        else:
            for _type in self.server_metadata.keys():
                _val = self.server_metadata[_type].get(claim)
                if _val:
                    return _val
            raise KeyError(f"{claim} not in server metadata")


class FederationClientEntity(ClientUnit):

    def __init__(
            self,
            upstream_get: Callable = None,
            keyjar: Optional[KeyJar] = None,
            config: Optional[Union[dict, Configuration]] = None,
            httpc: Optional[Callable] = None,
            httpc_params: Optional[dict] = None,
            services: Optional[dict] = None,
            jwks_uri: Optional[str] = "",
            metadata: Optional[dict] = None,
            trust_marks: Optional[list] = None,
            priority: Optional[list] = None,
            entity_id: Optional[str] = ""
    ):
        """

        :param keyjar: A py:class:`idpyoidc.key_jar.KeyJar` instance
        :param config: Configuration information passed on to the
            :py:class:`idpyoidc.client.service_context.ServiceContext`
            initialization
        :param httpc: A HTTP client to use
        :param services: A list of service definitions
        :param jwks_uri: A jwks_uri
        :param httpc_params: HTTP request arguments
        :return: Client instance
        """

        ClientUnit.__init__(self, upstream_get=upstream_get, httpc=httpc,
                            keyjar=keyjar, httpc_params=httpc_params,
                            config=config)

        _srvs = services or DEFAULT_FEDERATION_ENTITY_SERVICES

        self.service = init_services(service_definitions=_srvs, upstream_get=self.unit_get)

        self.context = FederationServiceContext(config=config,
                                                upstream_get=self.unit_get,
                                                metadata=metadata,
                                                trust_marks=trust_marks,
                                                priority=priority)

        self.setup_client_authn_methods(config)

    def get_attribute(self, attr, *args):
        val = getattr(self, attr)
        if val:
            return val
        else:
            return self.upstream_get('attribute', attr)

    def get_service(self, service_name, *arg):
        try:
            return self.service[service_name]
        except KeyError:
            return None

    def get_service_names(self, *args):
        return set(self.service.keys())

    def get_services(self, *args):
        return self.service.values()

    def get_context(self, *args):
        return self.context

    def setup_client_authn_methods(self, config):
        if config and "client_authn_methods" in config:
            self.context.client_authn_methods = client_auth_setup(
                config.get("client_authn_methods")
            )
        else:
            self.context.client_authn_methods = {}

    def set_client_id(self, client_id):
        self.context.client_id = client_id

    def get_context_attribute(self, attr, **args):
        _val = getattr(self.context, attr)
        if not _val:
            return self.upstream_get('context_attribute', attr)


class FederationClient(FederationClientEntity):
    client_type = ""

    def __init__(
            self,
            keyjar: Optional[KeyJar] = None,
            config: Optional[Union[dict, Configuration]] = None,
            services: Optional[dict] = None,
            httpc: Optional[Callable] = None,
            httpc_params: Optional[dict] = None,
            context: Optional[FederationContext] = None,
            upstream_get: Optional[Callable] = None,
            key_conf: Optional[dict] = None,
            entity_id: Optional[str] = "",
            verify_ssl: Optional[bool] = True,
            jwks_uri: Optional[str] = "",
            client_type: Optional[str] = "",
            **kwargs
    ):
        """

        :type client_type: str
        :param client_type: What kind of client this is. Presently 'oauth2' or 'oidc'
        :param keyjar: A py:class:`idpyoidc.key_jar.KeyJar` instance
        :param config: Configuration information passed on to the
            :py:class:`idpyoidc.client.service_context.ServiceContext`
            initialization
        :param httpc: A HTTP client to use
        :param httpc_params: HTTP request arguments
        :param services: A list of service definitions
        :param jwks_uri: A jwks_uri
        :return: Client instance
        """

        if config is None:
            config = {}

        if client_type:
            self.client_type = client_type
        elif config and 'client_type' in config:
            self.client_type = config["client_type"]

        if verify_ssl is False:
            # just ignore verify_ssl until it goes away
            if httpc_params:
                httpc_params["verify"] = False
            else:
                httpc_params = {"verify": False}

        jwks_uri = jwks_uri or config.get('jwks_uri', '')

        FederationClientEntity.__init__(
            self,
            keyjar=keyjar,
            config=config,
            services=services,
            jwks_uri=jwks_uri,
            httpc=httpc,
            httpc_params=httpc_params,
            upstream_get=upstream_get,
            entity_id=entity_id,
        )

        self.httpc = httpc or request

        if isinstance(config, Configuration):
            _add_ons = config.conf.get("add_ons")
        else:
            _add_ons = config.get("add_ons")

        if _add_ons:
            do_add_ons(_add_ons, self.service)

    def do_request(
            self,
            request_type: str,
            response_body_type: Optional[str] = "",
            request_args: Optional[dict] = None,
            behaviour_args: Optional[dict] = None,
            **kwargs
    ):
        _srv = self.service[request_type]
        self.context.issuer = kwargs.get("entity_id", kwargs.get("issuer"))
        _info = _srv.get_request_parameters(request_args=request_args,
                                            behaviour_args=behaviour_args, **kwargs)
        if not _info:
            return None

        if not response_body_type:
            response_body_type = _srv.response_body_type

        logger.debug("do_request info: {}".format(_info))

        _state = kwargs.get("state", "")
        return self.service_request(
            _srv, response_body_type=response_body_type, state=_state,
            behaviour_args=behaviour_args, **_info
        )

    def set_client_id(self, client_id):
        self.get_context().set("client_id", client_id)

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
        _data = kwargs.get("data")
        if _data and not body:
            body = _data

        try:
            resp = self.httpc(method, url, data=body, headers=headers, **self.httpc_params)
        except Exception as err:
            logger.error("Exception on request: {}".format(err))
            raise

        if 300 <= resp.status_code < 400:
            return {"http_response": resp}
        elif resp.status_code >= 400:
            logger.error(f"HTTP error: {resp}")
            return service.error_msg(error="System error", error_description=f"{resp.text}")
        if resp.status_code < 300:
            if "keyjar" not in kwargs:
                kwargs["keyjar"] = self.get_attribute("keyjar")
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

        _get_response_func = getattr(self, "get_response_ext", getattr(self, "get_response"))
        response = _get_response_func(
            service, url, method, body, response_body_type, headers, **kwargs
        )

        if "error" in response:
            pass
        else:
            service.update_service_context(response, key=kwargs.get("state"), **kwargs)
        return response

    def parse_request_response(self, service, reqresp, response_body_type="", state="", **kwargs):
        """
        Deal with a self.httpc response. The response are expected to
        follow a special pattern, having the attributes:

            - headers (list of tuples with headers attributes and their values)
            - status_code (integer)
            - text (The text version of the response)
            - url (The calling URL)

        :param service: A :py:class:`idpyoidc.client.service.Service` instance
        :param reqresp: The HTTP request response
        :param response_body_type: If response in body one of 'json', 'jwt', 'jose' or
            'urlencoded'
        :param state: Session identifier
        :param kwargs: Extra keyword arguments
        :return:
        """

        # if not response_body_type:
        #     response_body_type = self.response_body_type

        if reqresp.status_code in SUCCESSFUL:
            logger.debug('response_body_type: "{}"'.format(response_body_type))
            ctype = get_content_type(reqresp)
            _deser_method = get_deserialization_method(ctype)

            if _deser_method != response_body_type:
                logger.warning(
                    "Not the body type I expected: {} != {}".format(
                        _deser_method, response_body_type
                    )
                )
            if _deser_method in ["json", "jwt", "urlencoded"]:
                value_type = _deser_method
            else:
                value_type = response_body_type

            logger.debug(f"Successful response: {reqresp.text}")

            try:
                return service.parse_response(reqresp.text, value_type, state, **kwargs)
            except Exception as err:
                logger.error(err)
                raise
        elif reqresp.status_code in [302, 303]:  # redirect
            return reqresp
        elif reqresp.status_code == 500:
            logger.error("(%d) %s" % (reqresp.status_code, reqresp.text))
            raise ParseError("ERROR: Something went wrong: %s" % reqresp.text)
        elif 400 <= reqresp.status_code < 500:
            logger.error("Error response ({}): {}".format(reqresp.status_code, reqresp.text))
            # expecting an error response
            ctype = get_content_type(reqresp)
            _deser_method = get_deserialization_method(ctype)
            if not _deser_method:
                _deser_method = "json"

            try:
                err_resp = service.parse_response(reqresp.text, _deser_method)
            except (FormatError, ValueError):
                if _deser_method != response_body_type:
                    try:
                        err_resp = service.parse_response(reqresp.text, response_body_type)
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
            logger.error("Error response ({}): {}".format(reqresp.status_code, reqresp.text))
            raise OidcServiceError(
                "HTTP ERROR: %s [%s] on %s" % (reqresp.text, reqresp.status_code, reqresp.url)
            )

    def get_metadata(self, *args):
        metadata = self.context.claims.get_use()
        return {self.name: metadata}
