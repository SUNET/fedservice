import logging
from json import JSONDecodeError
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from idpyoidc.client.client_auth import client_auth_setup
from idpyoidc.client.client_auth import method_to_item
from idpyoidc.client.defaults import SUCCESSFUL
from idpyoidc.client.exception import OidcServiceError
from idpyoidc.client.oidc.rp import RP
from idpyoidc.client.service import REQUEST_INFO
from idpyoidc.client.service import Service
from idpyoidc.client.util import do_add_ons
from idpyoidc.client.util import get_deserialization_method
from idpyoidc.configure import Configuration
from idpyoidc.context import OidcContext
from idpyoidc.exception import FormatError
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import ResponseMessage

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


class ClientEntity(RP):
    name = 'openid_relying_party'
    entity_type = 'openid_relying_party'

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
            key_config: Optional[dict] = None,
            client_type: Optional[str] = '',
            entity_type: Optional[str] = '',
            **kwargs
    ):
        if config is None:
            config = {}

        for attr in ['preference', 'redirect_uris', 'server_type', 'endpoint', 'base_url',
                     'client_id', 'client_secret', 'client_authn_methods']:
            _val = kwargs.get(attr)
            if _val:
                config[attr] = _val

        self.metadata_class = None
        self.set_type(client_type, entity_type, config)

        self.entity_id = entity_id or config.get("entity_id", config.get("client_id", ""))

        if config.get("base_url", None) is None:
            config['base_url'] = self.entity_id

        if 'metadata' in config:
            config.update(config['metadata'])
            del config['metadata']

        self.metadata = {}

        services = services or config.get("services")
        if not services:
            if self.entity_type == 'openid_relying_party':
                services = COMBINED_DEFAULT_OIDC_SERVICES
            else:
                services = COMBINED_DEFAULT_OAUTH2_SERVICES

        RP.__init__(self,
                    keyjar=keyjar,
                    config=config,
                    services=services,
                    httpc=httpc,
                    httpc_params=httpc_params,
                    context=context,
                    upstream_get=upstream_get,
                    key_conf=key_config,
                    entity_id=self.entity_id,
                    jwks_uri=jwks_uri,
                    client_type=self.client_type
                    )

        # self.do_services(services=services, config=config)

        if "add_ons" in config:
            do_add_ons(self.context, config["add_ons"], self.context[''].service)

        # What's the default ? explicit/automatic ? automatic for the time being.
        _preference = config.get("preference")
        if _preference:
            registration_types = _preference.get("client_registration_types", [DEFAULT_REGISTRATION_TYPE])
        else:
            registration_types = [DEFAULT_REGISTRATION_TYPE]

        if "automatic" not in registration_types:
            authz_service = self.context[''].service.get("authorization")
            # Is it safe to assume it's the last item ? Such that I can use
            # authz_service.pre_construct.pop()
            # Probably not!
            try:
                authz_service.pre_construct.remove(authz_service._automatic_registration)
            except AttributeError:
                pass

    def set_type(self, client_type: Optional[str] = '',
                 entity_type: Optional[str] = '', config: Optional[Union[dict, Configuration]] = None):
        self.client_type = config.get('client_type', client_type)
        self.entity_type = config.get("entity_type", entity_type)
        if not self.client_type:
            self.client_type = ENTITY2CLIENT_TYPE.get(self.entity_type, "")
            if not self.client_type:
                self.client_type = ENTITY2CLIENT_TYPE[self.name]

        if self.client_type == "oauth2":
            self.metadata_class = OauthClientMetadata
        else:
            self.metadata_class = OIDCRPMetadata

    def setup_client_authn_methods(self, config, context):
        if config and "client_authn_methods" in config:
            _methods = config.get("client_authn_methods")
            context.client_authn_methods = client_auth_setup(method_to_item(_methods))
        else:
            context.client_authn_methods = {}

    def get_services(self, server_entity_id: Optional[str] = '', *arg):
        return self.context[server_entity_id].service

    def get_context(self, server_entity_id: Optional[str] = '', *arg):
        if isinstance(self.context, dict):
            return self.context[server_entity_id]
        else:
            return self.context

    def get_service(self, service_name, server_entity_id: Optional[str] = '', *arg):
        try:
            return self.context[server_entity_id].service[service_name]
        except KeyError:
            return None

    def get_service_by_endpoint_name(self, endpoint_name, server_entity_id: Optional[str] = '', *arg):
        for service in self.context[server_entity_id].service.values():
            if service.endpoint_name == endpoint_name:
                return service

        return None

    def get_entity(self):
        return self

    def get_client_id(self, *args):
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
            server_entity_id: Optional[str] = '',
            **kwargs
    ):
        _srv = self.get_service(request_type, server_entity_id)

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

    def set_client_id(self, client_id, *args):
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
                kwargs["keyjar"] = self.context.keyjar
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
