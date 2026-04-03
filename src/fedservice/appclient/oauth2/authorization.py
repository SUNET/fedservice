import logging

from idpyoidc.client.exception import OtherError
from idpyoidc.client.oauth2 import authorization
from idpyoidc.client.oauth2.add_on.jar import construct_request_parameter
from idpyoidc.exception import UnSupported
from idpyoidc.util import conf_get

logger = logging.getLogger(__name__)


# The two variants of authorization
def use_authorization_endpoint(entity, context, post_args, ams, entity_type):
    if 'pushed_authorization' in context.add_on:
        # Turn off pushed auth
        context.add_on['pushed_authorization']['apply'] = False

    if "request_object" in ams['authorization_endpoint']:
        post_args['request_param'] = "request"
        post_args['recv'] = context.get_metadata_claim("authorization_endpoint", [entity_type])
        post_args["with_jti"] = True
        post_args["lifetime"] = entity.conf.get("request_object_expires_in", 300)
        post_args['issuer'] = entity.upstream_get('attribute', 'entity_id')
    else:
        raise OtherError("Using request object in authentication not supported by OP")

    return post_args


def use_pushed_authorization_endpoint(entity, context, post_args, ams, entity_type):
    if 'pushed_authorization' not in context.add_on:
        raise UnSupported('Pushed Authorization not supported')
    else:  # Make it happen
        context.add_on['pushed_authorization']['apply'] = True


def automatic_registration(request_args, service, post_args=None, **kwargs):
    _context = service.upstream_get("context")
    if post_args is None:
        post_args = {}

    _request_endpoints = conf_get(_context.config, 'authorization_request_endpoints',
                                  ["authorization_endpoint", "pushed_authorization_request_endpoint"]  # default
                                  )

    # What does the server support
    _client_type = service.upstream_get('attribute', "client_type")
    if _client_type == 'oidc':
        _entity_type = "openid_provider"
    elif _client_type == 'oauth2':
        _entity_type = "oauth_authorization_server"
    else:
        raise KeyError(f"Unknown client_type: {_client_type}")

    _auth_meth_supported = _context.get_metadata_claim('request_authentication_methods_supported', [_entity_type])

    # what if request_param is already set ??
    # What if request_param in not in client_auth ??
    if _auth_meth_supported:
        for endpoint in _request_endpoints:
            if endpoint in _auth_meth_supported:
                _func = getattr(service, f'_use_{endpoint}')
                post_args = _func(service, _context, post_args, _auth_meth_supported, _entity_type)
                break
    else:  # The OP does not support any authn methods
        # am I already registered ?
        if not _context.registration_response:  # Not registered
            raise OtherError("Can not send an authorization request without being registered"
                             " and automatic registration not supported")

    client_id = request_args.get('client_id')
    if not client_id:
        request_args['client_id'] = service.upstream_get('attribute', 'entity_id')

    return request_args, post_args


def create_request(request_args, **kwargs):
    request_arg = kwargs.get('request_param', "")
    if request_arg == "request":
        service = kwargs.get("service")
        del kwargs["service"]
        _args = {k: request_args[k] for k in service.msg_type().required_parameters() if k in request_args}
        _req = construct_request_parameter(service, request_args, **kwargs)
        _args["request"] = _req
        return service.msg_type(**_args)
    else:
        return request_args


class Authorization(authorization.Authorization):

    def __init__(self, upstream_get, conf=None):
        authorization.Authorization.__init__(self, upstream_get=upstream_get, conf=conf)
        self.pre_construct.append(automatic_registration)
        self.post_construct.append(create_request)

        self._use_authorization_endpoint = use_authorization_endpoint
        self._use_pushed_authorization_endpoint = use_pushed_authorization_endpoint

