import json
import logging
import sys
import traceback

import werkzeug
from fedservice.entity_statement.create import create_entity_configuration
from flask import Blueprint
from flask import current_app
from flask import redirect
from flask import request
from flask.helpers import make_response
from flask.helpers import send_from_directory
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.server.exception import InvalidClient
from idpyoidc.server.exception import UnknownClient

logger = logging.getLogger(__name__)

entity = Blueprint('entity', __name__, url_prefix='')


def _add_cookie(resp, cookie_spec):
    kwargs = {'value': cookie_spec["value"]}
    for param in ['expires', 'max-age']:
        if param in cookie_spec:
            kwargs[param] = cookie_spec[param]
    kwargs["path"] = "/"
    resp.set_cookie(cookie_spec["name"], **kwargs)


def add_cookie(resp, cookie_spec):
    if isinstance(cookie_spec, list):
        for _spec in cookie_spec:
            _add_cookie(resp, _spec)
    elif isinstance(cookie_spec, dict):
        _add_cookie(resp, cookie_spec)


def do_response(endpoint, req_args, error='', **args):
    info = endpoint.do_response(request=req_args, error=error, **args)
    _log = current_app.logger
    _log.debug('do_response: {}'.format(info))

    try:
        _response_placement = info['response_placement']
    except KeyError:
        _response_placement = endpoint.response_placement

    _log.debug('response_placement: {}'.format(_response_placement))

    if error:
        if _response_placement == 'body':
            _log.info('Error Response: {}'.format(info['response']))
            resp = make_response(info['response'], 400)
        else:  # _response_placement == 'url':
            _log.info('Redirect to: {}'.format(info['response']))
            resp = redirect(info['response'])
    else:
        if _response_placement == 'body':
            _log.info('Response: {}'.format(info['response']))
            resp = make_response(info['response'], 200)
        else:  # _response_placement == 'url':
            _log.info('Redirect to: {}'.format(info['response']))
            resp = redirect(info['response'])

    for key, value in info['http_headers']:
        resp.headers[key] = value

    if 'cookie' in info:
        add_cookie(resp, info['cookie'])

    return resp


def service_endpoint(endpoint):
    _log = current_app.logger
    _log.info('At the "{}" endpoint'.format(endpoint.name))

    if request.method == 'GET':
        if request.args:
            req_args = request.args.to_dict()
        else:
            req_args = {}
    else:
        if request.data:
            if isinstance(request.data, str):
                req_args = request.data
            else:
                req_args = request.data.decode()
        else:
            req_args = dict([(k, v) for k, v in request.form.items()])

    try:
        req_args = endpoint.parse_request(req_args)
    except (InvalidClient, UnknownClient) as err:
        _log.error(err)
        return make_response(json.dumps({
            'error': 'unauthorized_client',
            'error_description': str(err)
        }), 400)
    except Exception as err:
        _log.error(err)
        err_msg = ResponseMessage(error='invalid_request', error_description=str(err))
        return make_response(err_msg.to_json(), 400)

    _log.info('request: {}'.format(req_args))
    if isinstance(req_args, ResponseMessage) and 'error' in req_args:
        return make_response(req_args.to_json(), 400)

    try:
        args = endpoint.process_request(req_args)
    except Exception as err:
        message = traceback.format_exception(*sys.exc_info())
        _log.error(message)
        err_msg = ResponseMessage(error='invalid_request', error_description=str(err))
        return make_response(err_msg.to_json(), 400)

    _log.info('Response args: {}'.format(args))

    if 'redirect_location' in args:
        return redirect(args['redirect_location'])
    if 'http_response' in args:
        resp = make_response(args['http_response'], 200)
        #resp.headers['content-type'] = endpoint.response_content_type
        return resp

    response = do_response(endpoint, req_args, **args)
    return response


@entity.route('/static/<path:path>')
def send_js(path):
    return send_from_directory('static', path)


@entity.route('/fetch')
def fetch():
    _endpoint = current_app.federation_entity.get_endpoint('fetch')
    return service_endpoint(_endpoint)


@entity.route('/list')
def list():
    _endpoint = current_app.federation_entity.get_endpoint('list')
    return service_endpoint(_endpoint)


@entity.errorhandler(werkzeug.exceptions.BadRequest)
def handle_bad_request(e):
    return 'bad request!', 400


@entity.route('/trust_mark')
def trust_mark():
    _endpoint = current_app.federation_entity.get_endpoint('trust_mark')
    return service_endpoint(_endpoint)


@entity.route('/trust_mark_status')
def trust_mark_status():
    _endpoint = current_app.federation_entity.get_endpoint('trust_mark_status')
    return service_endpoint(_endpoint)


@entity.route('/trust_mark_list')
def trust_mark_list():
    _endpoint = current_app.federation_entity.get_endpoint('trust_mark_list')
    return service_endpoint(_endpoint)

@entity.route('/.well-known/openid-federation')
def wkof():
    _entity = current_app.server
    metadata = _entity.get_metadata()
    _fe = current_app.federation_entity
    _ctx = _fe.context
    iss = _ctx.entity_id
    _statement = create_entity_configuration(
        iss=iss, key_jar=_fe.keyjar, metadata=metadata, authority_hints=_fe.get_authority_hints(),
        lifetime=_ctx.default_lifetime, include_jwks=True)

    response = make_response(_statement)
    response.headers['Content-Type'] = 'application/jose; charset=UTF-8'
    return response