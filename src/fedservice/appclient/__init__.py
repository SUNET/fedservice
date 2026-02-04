import logging
from json import JSONDecodeError
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from cryptojwt.key_bundle import keybundle_from_local_file
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
from idpyoidc.key_import import add_kb
from idpyoidc.key_import import import_jwks_from_file
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import is_error_message
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.util import keyjar_combination

from fedservice import save_trust_chains
from fedservice.defaults import COMBINED_DEFAULT_OAUTH2_SERVICES
from fedservice.defaults import COMBINED_DEFAULT_OIDC_SERVICES
from fedservice.defaults import DEFAULT_REGISTRATION_TYPE
from fedservice.defaults import REGISTER2PREFERRED
from fedservice.entity.function import get_verified_trust_chains
from fedservice.entity.utils import get_federation_entity
from fedservice.exception import NoTrustedChains
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
    metadata_class = OIDCRPMetadata

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
                    client_type=self.client_type,
                    metadata_class=self.metadata_class,
                    register2preferred=REGISTER2PREFERRED
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

    def get_service(self, context, service_name, *arg):
        try:
            return context.service[service_name]
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
            context,
            request_type: str,
            response_body_type: Optional[str] = "",
            request_args: Optional[dict] = None,
            behaviour_args: Optional[dict] = None,
            **kwargs
    ):
        # _srv = self.get_service(request_type, server_entity_id)
        _srv = context.service[request_type]

        _info = _srv.get_request_parameters(context, request_args=request_args, **kwargs)
        _info['server_entity_id'] = context.get("issuer", "")

        if not response_body_type:
            response_body_type = _srv.response_body_type

        logger.debug(f"do_request info: {_info}")

        try:
            _state = kwargs["state"]
        except:
            _state = ""
        return self.service_request(
            context, _srv, response_body_type=response_body_type, state=_state, **_info
        )

    def set_client_id(self, client_id, *args):
        self.context.set("client_id", client_id)

    def get_response(
            self,
            context,
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
                server_entity_id = kwargs.get("server_entity_id", "")
                kwargs["keyjar"] = keyjar_combination(self, server_entity_id=server_entity_id)
                # kwargs["keyjar"] = self.context[server_entity_id].keyjar
            if not response_body_type:
                response_body_type = service.response_body_type

            if response_body_type == "html":
                return resp.text

            if body:
                kwargs["request_body"] = body
        if resp.status_code >= 400:
            logger.error(f"Exception on request: {resp.text}")
            return {}

        return self.parse_request_response(context, service, resp, response_body_type, **kwargs)

    def service_request(
            self,
            context,
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

        # returns
        response = self.get_response(
            context, service, url, method, body, response_body_type, headers, **kwargs
        )

        if "error" in response:
            pass
        else:
            try:
                kwargs["key"] = kwargs["state"]
            except KeyError:
                pass

            service.update_service_context(context, response, **kwargs)
        return response

    def _parse_unsigned_reponse(self, response, deser_method):
        if deser_method == 'json':
            err_resp = ResponseMessage().from_json(response).to_dict()
        elif deser_method == "urlencoded":
            err_resp = ResponseMessage().from_urlencoded(response).to_dict()
        else:
            err_resp = {"error": response}

        return err_resp

    def _parse_signed_response(self, context, service, response, deser_method, state, **kwargs):
        return service.parse_response(context, response, deser_method, state, **kwargs)

    def _parse_response(self, context, service, response, body_type, state, **kwargs):
        try:
            return self._parse_signed_response(context, service, response, body_type, state, **kwargs)
        except Exception:
            _resp = self._parse_unsigned_reponse(response, body_type)
            logger.warning('Unsigned response')
            return _resp

    def parse_request_response(self, context, service, reqresp, response_body_type="", state="", **kwargs):
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
                return self._parse_signed_response(context, service, reqresp.text, body_type, state,
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
                err_resp = self._parse_response(context, service, reqresp.text, content_type, state,
                                                **kwargs)
            except (FormatError, ValueError):
                if content_type != response_body_type:
                    logger.warning(f'Response with wrong content-type: {content_type}')
                    try:
                        err_resp = self._parse_response(context,
                                                        service,
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

    def do_provider_info(
            self,
            rp_context,
            behaviour_args: Optional[dict] = None,
    ) -> str:
        """
        Get the provider metadata using OpenID Federation.

        :param behaviour_args: Behaviour specific attributes
        :return: issuer ID
        """
        logger.debug(20 * "*" + " do_provider_info@openid.federation " + 20 * "*")

        _federation_entity = get_federation_entity(self)

        _pi = rp_context.get("provider_info", None)
        if _pi is None or _pi == {}:
            _pi = self._collect_metadata(_federation_entity, rp_context.issuer)
        elif len(_pi) == 1 and "issuer" in _pi:
            rp_context.issuer = _pi["issuer"]
            _pi = self._collect_metadata(_federation_entity, rp_context.issuer)
        else:
            for key, val in _pi.items():
                # All service endpoint parameters in the provider info has
                # a name ending in '_endpoint' so I can look specifically
                # for those
                if key.endswith("_endpoint"):
                    for _srv in self.get_services().values():
                        # Every service has an endpoint_name assigned
                        # when initiated. This name *MUST* match the
                        # endpoint names used in the provider info
                        if _srv.endpoint_name == key:
                            _srv.endpoint = val

            if "keys" in _pi:
                _kj = self.get_attribute("keyjar")
                for typ, _spec in _pi["keys"].items():
                    if typ == "url":
                        for _iss, _url in _spec.items():
                            _kj.add_url(_iss, _url)
                    elif typ == "file":
                        for kty, _name in _spec.items():
                            if kty == "jwks":
                                _kj = import_jwks_from_file(_kj, _name, rp_context.get("issuer"))
                            elif kty == "rsa":  # PEM file
                                _kb = keybundle_from_local_file(_name, "der", ["sig"])
                                _kj = add_kb(_kj, rp_context.get("issuer"), _kb)
                    else:
                        raise ValueError("Unknown provider JWKS type: {}".format(typ))

        rp_context.map_supported_to_preferred(info=_pi)

        try:
            return rp_context.provider_info["issuer"]
        except:
            return rp_context.issuer

    def _import_keys(self, resp, keyjar, issuer):
        if "jwks_uri" in resp:
            logger.debug(f"'jwks_uri' in provider info: {resp['jwks_uri']}")
            _hp = self.httpc_params
            if _hp:
                if "verify" in _hp and "verify" not in keyjar.httpc_params:
                    keyjar.httpc_params["verify"] = _hp["verify"]
            keyjar.load_keys(issuer, jwks_uri=resp["jwks_uri"])
        elif "jwks" in resp:
            logger.debug("'jwks' in provider info")
            keyjar.load_keys(issuer, jwks=resp["jwks"])
        else:
            logger.debug("Neither jws or jwks_uri in provider info")

    def _collect_metadata(self, federation_entity, server_entity_id):
        context = federation_entity.context
        _trust_chains = get_verified_trust_chains(self, server_entity_id)
        if _trust_chains:
            save_trust_chains(context, _trust_chains)
            trust_chain = federation_entity.pick_trust_chain(_trust_chains)
            federation_entity.context.trust_chain_anchor[server_entity_id] = trust_chain.anchor
            #
            _pi = trust_chain.metadata["openid_provider"]
            context.trust_chain[_pi["issuer"]] = trust_chain

            combo = federation_entity.upstream_get('unit')
            rp = combo['openid_relying_party']
            rp.context[server_entity_id].provider_info = context.metadata = _pi
            self._import_keys(_pi, rp.context[server_entity_id].keyjar, _pi["issuer"])
            return _pi
        else:
            raise NoTrustedChains(server_entity_id)

    def finalize(self, response, behaviour_args: Optional[dict] = None):
        """
        The third of the high level methods that a user of this Class should
        know about.
        Once the consumer has redirected the user back to the
        callback URL there might be a number of services that the client should
        use. Which one those are defined by the client configuration.

        :param behaviour_args: For finetuning
        :param issuer: Who sent the response
        :param response: The Authorization response as a dictionary
        :returns: An dictionary with the following keys:
            **state** The key under which the session information is
            stored in the data store and
            **token** The access token
            **id_token:: the ID Token
            **userinfo** The collected user information
            **session_state** If logout is supported the special session_state claim
        """

        authorization_response = self.finalize_auth(response)
        if is_error_message(authorization_response):
            return {
                "state": authorization_response["state"],
                "error": authorization_response["error"],
            }

        _state = authorization_response["state"]

        rp_context = self.state2context(authorization_response)

        token = self.get_access_and_id_token(
            rp_context, authorization_response, state=_state, behaviour_args=behaviour_args
        )
        _id_token = token.get("id_token")
        logger.debug(f"ID Token: {_id_token}")

        if self.get_service(rp_context, "userinfo") and token["access_token"]:
            inforesp = self.get_user_info(
                rp_context,
                state=authorization_response["state"],
                access_token=token["access_token"],
            )

            if isinstance(inforesp, ResponseMessage) and "error" in inforesp:
                return {"error": "Invalid response %s." % inforesp["error"], "state": _state}

        elif _id_token:  # look for it in the ID Token
            inforesp = self.userinfo_in_id_token(_id_token)
        else:
            inforesp = {}

        logger.debug("UserInfo: %s", inforesp)

        try:
            _sid_support = rp_context.get("provider_info")["backchannel_logout_session_required"]
        except KeyError:
            try:
                _sid_support = rp_context.get("provider_info")["frontchannel_logout_session_required"]
            except Exception:
                _sid_support = False

        if _sid_support and _id_token:
            try:
                sid = _id_token["sid"]
            except KeyError:
                pass
            else:
                rp_context.cstate.bind_key(sid, _state)

        if _id_token:
            rp_context.cstate.bind_key(_id_token["sub"], _state)
        else:
            rp_context.cstate.bind_key(inforesp["sub"], _state)

        return {
            "userinfo": inforesp,
            "state": authorization_response["state"],
            "token": token["access_token"],
            "id_token": _id_token,
            "session_state": authorization_response.get("session_state", ""),
            "issuer": rp_context.issuer,
        }

    def do_client_registration(
            self,
            context,
            request_args: Optional[dict] = None,
            behaviour_args: Optional[dict] = None,
            issuer: Optional[str] = ""
    ):
        if 'explicit' not in context.claims.use['client_registration_types']:
            logger.debug("Doing automatic client registration")
            return

        return super().do_client_registration(self, context, request_args, behaviour_args, issuer)
