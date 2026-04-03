import logging
from typing import Optional
from urllib.parse import urlparse

from cryptojwt.jws.utils import alg2keytype
from cryptojwt.jwt import utc_time_sans_frac
from cryptojwt.utils import as_bytes
from cryptojwt.utils import importer
from idpyoidc.exception import MessageException
from idpyoidc.message import oauth2
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.server import Endpoint
from idpyoidc.server.exception import CapabilitiesMisMatch
from idpyoidc.server.exception import InvalidRedirectURIError
from idpyoidc.server.oidc import registration
from idpyoidc.server.oidc.registration import comb_uri
from idpyoidc.server.oidc.registration import secret
from idpyoidc.server.oidc.registration import verify_url
from idpyoidc.util import rndstr
from idpyoidc.util import sanitize
from idpyoidc.util import split_uri

from fedservice import save_trust_chains
from fedservice.appserver import import_client_keys
from fedservice.entity.function import apply_policies
from fedservice.entity.function import get_verified_trust_chains
from fedservice.entity.function.trust_chain_collector import verify_self_signed_signature
from fedservice.entity.utils import get_federation_entity
from fedservice.exception import NoTrustedChains
from fedservice.message import OauthClientInformationResponse

logger = logging.getLogger(__name__)


class Registration(Endpoint):
    msg_type = oauth2.OauthClientMetadata
    response_cls = OauthClientInformationResponse
    request_format = 'jose'
    request_placement = 'body'
    response_format = 'jose'
    endpoint_name = "federation_registration_endpoint"
    name = "registration"
    _supports = {
        "client_registration_types_supported": ["automatic", "explicit"]
    }

    def __init__(self, upstream_get, **kwargs):
        Endpoint.__init__(self, upstream_get, **kwargs)
        self.post_construct.append(self.create_entity_statement)
        _seed = kwargs.get("seed") or rndstr(32)
        self.seed = as_bytes(_seed)

    def parse_request(self, request, auth=None, **kwargs):
        return request

    def process_request(self, request=None, **kwargs):
        """

        :param request: An entity statement in the form of a signed JT
        :param kwargs:
        :return:
        """
        payload = verify_self_signed_signature(request)
        opponent_entity_type = set(payload['metadata'].keys()).difference({'federation_entity',
                                                                           'trust_mark_issuer'}).pop()
        _federation_entity = get_federation_entity(self)

        # Collect trust chains for client
        _trust_chains = get_verified_trust_chains(self, entity_id=payload['sub'])
        if not _trust_chains:
            raise NoTrustedChains(f"No trust chains for {payload['sub']}")

        save_trust_chains(self.upstream_get("context"), _trust_chains)

        _trust_chains = apply_policies(_federation_entity, _trust_chains)
        trust_chain = _federation_entity.pick_trust_chain(_trust_chains)
        _federation_entity.trust_chain_anchor = trust_chain.anchor

        # Perform non-federation registration
        req = oauth2.OauthClientMetadata(**payload['metadata'][opponent_entity_type])
        response_info = self.step2_process_request(req, **kwargs)
        if "response_args" in response_info:
            _context = _federation_entity.context
            _response_metadata = req.to_dict()
            _response_metadata.update(response_info['response_args'])

            entity_statement = _context.create_entity_configuration(
                _federation_entity.upstream_get('attribute', 'entity_id'),
                # payload['iss'],
                trust_anchor=trust_chain.anchor,
                metadata={opponent_entity_type: _response_metadata},
                aud=payload['iss'],
                include_jwks=False
            )
            response_info["response_msg"] = entity_statement
            del response_info["response_args"]

        return response_info

    def match_claim(self, claim, val):
        _context = self.upstream_get("context")

        # Use my defaults
        _my_key = _context.claims.register2preferred.get(claim, claim)
        try:
            _val = _context.provider_info[_my_key]
        except KeyError:
            return val

        try:
            _claim_spec = _context.claims.registration_response.c_param[claim]
        except KeyError:  # something I don't know anything about
            return None

        if _val:
            if isinstance(_claim_spec[0], list):
                if isinstance(val, str):
                    if val in _val:
                        return val
                else:
                    _ret = list(set(_val).intersection(set(val)))
                    if len(_ret) > 0:
                        return _ret
                    else:
                        raise CapabilitiesMisMatch(_my_key)
            else:
                if isinstance(_val, list):
                    if val in _val:
                        return val
                elif val == _val:
                    return val

        return None

    def filter_client_request(self, request: dict) -> dict:
        _args = {}
        _context = self.upstream_get("context")
        for key, val in request.items():
            if key not in _context.claims.register2preferred:
                _args[key] = val
                continue

            _val = self.match_claim(key, val)
            if _val:
                _args[key] = _val
            else:
                logger.error(f"Capabilities mismatch: {key}={val} not supported")
        return _args

    def client_secret_expiration_time(self):
        """
        Returns client_secret expiration time.
        """
        if not self.kwargs.get("client_secret_expires", True):
            return 0

        _expiration_time = self.kwargs.get("client_secret_expires_in", 2592000)
        return utc_time_sans_frac() + _expiration_time

    def add_client_secret(self, cinfo, client_id, context):
        client_secret = secret(self.seed, client_id)
        cinfo["client_secret"] = client_secret
        _eat = self.client_secret_expiration_time()
        if _eat:
            cinfo["client_secret_expires_at"] = _eat

        return client_secret

    @staticmethod
    def verify_redirect_uris(registration_request):
        verified_redirect_uris = []
        client_type = registration_request.get("application_type", "web")

        must_https = False
        if client_type == "web":
            must_https = True
            if registration_request.get("response_types") == ["code"]:
                must_https = False

        for uri in registration_request["redirect_uris"]:
            _custom = False
            p = urlparse(uri)
            if client_type == "native":
                if p.scheme not in ["http", "https"]:  # Custom scheme
                    _custom = True
                elif p.scheme == "http" and p.hostname in ["localhost", "127.0.0.1"]:
                    pass
                else:
                    logger.error(
                        "InvalidRedirectURI: scheme:%s, hostname:%s",
                        p.scheme,
                        p.hostname,
                    )
                    raise InvalidRedirectURIError(
                        "Redirect_uri must use custom " "scheme or http and localhost"
                    )
            elif must_https and p.scheme != "https":
                msg = "None https redirect_uri not allowed"
                raise InvalidRedirectURIError(msg)
            elif p.scheme not in ["http", "https"]:
                # Custom scheme
                raise InvalidRedirectURIError("Custom redirect_uri not allowed for web client")
            elif p.fragment:
                raise InvalidRedirectURIError("redirect_uri contains fragment")

            if _custom:  # Can not verify a custom scheme
                verified_redirect_uris.append((uri, {}))
            else:
                base, query = split_uri(uri)
                if query:
                    verified_redirect_uris.append((base, query))
                else:
                    verified_redirect_uris.append((base, {}))

        return verified_redirect_uris

    def do_client_registration(self, request, client_id, ignore=None):
        if ignore is None:
            ignore = []
        _context = self.upstream_get("context")
        _cinfo = _context.cdb[client_id].copy()
        logger.debug("_cinfo: %s" % sanitize(_cinfo))

        for key, val in request.items():
            if key not in ignore:
                _cinfo[key] = val

        _uri = request.get("post_logout_redirect_uri")
        if _uri:
            if urlparse(_uri).fragment:
                err = self.error_cls(
                    error="invalid_configuration_parameter",
                    error_description="post_logout_redirect_uri contains fragment",
                )
                return err
            _cinfo["post_logout_redirect_uri"] = split_uri(_uri)

        if "redirect_uris" in request:
            try:
                ruri = self.verify_redirect_uris(request)
                _cinfo["redirect_uris"] = ruri
            except InvalidRedirectURIError as e:
                return self.error_cls(error="invalid_redirect_uri", error_description=str(e))

        if "request_uris" in request:
            _uris = []
            for uri in request["request_uris"]:
                _up = urlparse(uri)
                if _up.query:
                    err = self.error_cls(
                        error="invalid_configuration_parameter",
                        error_description="request_uris contains query part",
                    )
                    return err
                if _up.fragment:
                    # store base and fragment
                    _uris.append(uri.split("#"))
                else:
                    _uris.append([uri, ""])
            _cinfo["request_uris"] = _uris

        for item in ["policy_uri", "logo_uri", "tos_uri"]:
            if item in request:
                if verify_url(request[item], _cinfo["redirect_uris"]):
                    _cinfo[item] = request[item]
                else:
                    return ResponseMessage(
                        error="invalid_configuration_parameter",
                        error_description="%s pointed to illegal URL" % item,
                    )

        _keyjar = self.upstream_get("attribute", "keyjar")
        # Do I have the necessary keys
        for item in ["id_token_signed_response_alg", "userinfo_signed_response_alg"]:
            if item in request:
                _claim = _context.claims.register2preferred[item]
                _support = _context.provider_info.get(_claim)
                if _support is None:
                    logger.warning(f'Lacking support for "{item}"')
                    del _cinfo[item]
                    continue

                if request[item] in _support:
                    ktyp = alg2keytype(request[item])
                    # do I have this ktyp and for EC type keys the curve
                    if ktyp not in ["none", "oct"]:
                        _k = []
                        for iss in ["", _context.issuer]:
                            _k.extend(
                                _keyjar.get_signing_key(ktyp, alg=request[item], issuer_id=iss)
                            )
                        if not _k:
                            logger.warning('Lacking support for "{}"'.format(request[item]))
                            del _cinfo[item]

        import_client_keys(request, _keyjar, client_id)
        logger.debug(f"Keys for {client_id}: {_keyjar.key_summary(client_id)}")

        return _cinfo

    def client_registration_setup(self, request,
                                  new_id: Optional[bool] = True,
                                  set_secret: Optional[bool] = True,
                                  reserved_client_id: Optional[list] = None):
        try:
            request.verify()
        except (MessageException, ValueError) as err:
            logger.error("request.verify() error on %s", request)
            _error = "invalid_configuration_request"
            if len(err.args) > 1:
                if err.args[1] == "initiate_login_uri":
                    _error = "invalid_client_claims"

            return ResponseMessage(error=_error, error_description="%s" % err)

        request.rm_blanks()
        _context = self.upstream_get("context")

        try:
            request = self.filter_client_request(request)
        except CapabilitiesMisMatch as err:
            return ResponseMessage(
                error="invalid_request",
                error_description="Don't support proposed %s" % err,
            )

        if new_id:
            if self.kwargs.get("client_id_generator"):
                cid_generator = importer(self.kwargs["client_id_generator"]["class"])
                cid_gen_kwargs = self.kwargs["client_id_generator"].get("kwargs", {})
            else:
                cid_generator = importer("idpyoidc.server.oidc.registration.random_client_id")
                cid_gen_kwargs = {}
            if not reserved_client_id:
                reserved_client_id = _context.cdb.keys()
            client_id = cid_generator(reserved=reserved_client_id, **cid_gen_kwargs)
            if "client_id" in request:
                del request["client_id"]
        else:
            client_id = request.get("client_id")
            if not client_id:
                raise ValueError("Missing client_id")

        _cinfo = {"client_id": client_id, "client_salt": rndstr(8)}

        # if self.upstream_get("endpoint", "registration_read"):
        #     self.add_registration_api(_cinfo, client_id, _context)

        if new_id:
            _cinfo["client_id_issued_at"] = utc_time_sans_frac()

        client_secret = ""
        if set_secret:
            client_secret = self.add_client_secret(_cinfo, client_id, _context)

        logger.debug("Stored client info in CDB under cid={}".format(client_id))

        _context.cdb[client_id] = _cinfo
        _cinfo = self.do_client_registration(
            request,
            client_id,
            ignore=["redirect_uris", "policy_uri", "logo_uri", "tos_uri"],
        )
        if isinstance(_cinfo, ResponseMessage):
            return _cinfo

        args = dict([(k, v) for k, v in _cinfo.items() if k in self.response_cls.c_param])

        comb_uri(args)
        response = self.response_cls(**args)

        # Add the client_secret as a symmetric key to the key jar
        if client_secret:
            self.upstream_get("attribute", "keyjar").add_symmetric(client_id, str(client_secret))

        logger.debug("Stored updated client info in CDB under cid={}".format(client_id))
        logger.debug("ClientInfo: {}".format(_cinfo))
        _context.cdb[client_id] = _cinfo

        # Not all databases can be sync'ed
        if hasattr(_context.cdb, "sync") and callable(_context.cdb.sync):
            _context.cdb.sync()

        msg = "registration_response: {}"
        logger.info(msg.format(sanitize(response.to_dict())))

        return response

    def step2_process_request(self, request=None, new_id=True, set_secret=True, **kwargs):
        try:
            reserved_client_id = kwargs.get("reserved")
            reg_resp = self.client_registration_setup(request, new_id, set_secret,
                                                      reserved_client_id)
        except Exception as err:
            logger.error("client_registration_setup: %s", request)
            return ResponseMessage(
                error="invalid_configuration_request", error_description="%s" % err
            )

        if "error" in reg_resp:
            return reg_resp
        else:
            _context = self.upstream_get("context")
            _cookie = _context.new_cookie(
                name=_context.cookie_handler.name["register"],
                client_id=reg_resp["client_id"],
            )

            return {"response_args": reg_resp, "cookie": _cookie, "response_code": 201}

    @staticmethod
    def create_entity_statement(response_args, request, context,
                                **kwargs):
        """
        wrap the non-federation response in a federation response

        :param response_args:
        :param request:
        :param context:
        :param kwargs:
        :return:
        """
        _fe = context.federation_entity
        _md = {_fe.opponent_entity_type: response_args.to_dict()}
        return _fe.create_entity_statement(_fe.entity_id, sub=_fe.entity_id,
                                           metadata=_md,
                                           authority_hints=_fe.get_authority_hints(),
                                           trust_marks=_fe.context.trust_marks)

    def non_fed_process_request(self, req, **kwargs):
        # handle the registration request as in the non-federation case.
        return registration.Registration.process_request(self, req, authn=None, **kwargs)
