import json
import logging
import sys
import traceback

import werkzeug
from flask import Blueprint
from flask import current_app
from flask import redirect
from flask import render_template
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
            _req_args = request.args.to_dict()
        else:
            _req_args = {}
        try:
            req_args = endpoint.parse_request(_req_args)
        except (InvalidClient, UnknownClient) as err:
            _log.error(err)
            return make_response(json.dumps({
                'error': 'unauthorized_client',
                'error_description': str(err)
            }), 400)
        except Exception as err:
            _log.error(err)
            return make_response(json.dumps({
                'error': 'invalid_request',
                'error_description': str(err)
            }), 400)
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
        return make_response(args['http_response'], 200)

    response = do_response(endpoint, req_args, **args)
    return response


@entity.route('/')
def index():
    _entity = current_app.federation_entity
    _keys = _entity.server.subordinate.keys()
    display = {k:_entity.server.subordinate[k] for k in _keys}
    return render_template('trust_anchor.html', subordinates=display)

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


@entity.route('/resolve')
def resolve():
    _endpoint = current_app.federation_entity.get_endpoint('resolve')
    return service_endpoint(_endpoint)


@entity.route('/pid_query')
def pid_query():
    _endpoint = current_app.federation_entity.get_endpoint('pid_query')
    return service_endpoint(_endpoint)

@entity.errorhandler(werkzeug.exceptions.BadRequest)
def handle_bad_request(e):
    return 'bad request!', 400


@entity.route('/.well-known/openid-federation')
def wkof():
    _fe = current_app.federation_entity
    metadata = _fe.get_metadata()
    _ctx = _fe.context
    iss = sub = _ctx.entity_id
    _statement = _ctx.create_entity_statement(
        metadata=metadata, iss=iss, sub=sub, authority_hints=_fe.get_authority_hints(),
        lifetime=_ctx.default_lifetime)

    response = make_response(_statement)
    if 'Content-Type' not in response.headers:
        response.headers['Content-Type'] = 'application/entity-statement+jwt'
    return response
