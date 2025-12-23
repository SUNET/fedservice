import logging
import time
from datetime import datetime
from typing import Callable

import werkzeug
from flask import Blueprint
from flask import current_app
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask.helpers import make_response
from flask.helpers import send_from_directory
from idpyoidc.client.exception import OidcServiceError
from idpyoidc.client.rp_handler import RPHandler

from fedservice.entity_statement.create import create_entity_statement

logger = logging.getLogger(__name__)

entity = Blueprint('oidc_rp', __name__, url_prefix='')


@entity.route('/static/<path:filename>')
def send_js(filename):
    return send_from_directory('static', filename)


@entity.route('/jwks/<guise>')
def keys(guise):
    if guise in ["openid_relying_party", "federation_entity"]:
        _ent_type = current_app.server[guise]
        logger.debug(f"Returning keys for {guise}")
        logger.debug(f"_ent_type: {_ent_type}")
        if isinstance(_ent_type, RPHandler):
            logger.debug(f"<<RPHandler>>")
            _json = _ent_type.keyjar.export_jwks_as_json()
        else:
            _context = _ent_type.get_context()
            _json = _context.keyjar.export_jwks_as_json()
        logger.debug(f"keys: {_json}")
        return _json

    return "Asking for something I do not have", 400


@entity.route('/')
def index():
    _providers = current_app.server["openid_relying_party"].client_configs.keys()
    return render_template('rpe_opbyuid.html', providers=_providers)


@entity.route('/irp')
def irp():
    return send_from_directory('entity_statements', 'irp.jws')


def get_rph():
    return current_app.server["openid_relying_party"]


# @entity.route('/<string:op_hash>/.well-known/openid-federation')
@entity.route('/.well-known/openid-federation')
def wkof():
    _rph = get_rph()
    if _rph.issuer2rp == {}:
        cli = _rph.init_client('dummy')
    else:
        # Any client will do
        cli = _rph.issuer2rp[list(_rph.issuer2rp.keys())[0]]

    _metadata = current_app.server.get_metadata(cli)
    #_metadata.update(cli.get_metadata())

    _fed_entity = current_app.server["federation_entity"]

    if _fed_entity.context.trust_marks:
        if isinstance(_fed_entity.context.trust_marks, Callable):
            args = {"trust_marks": _fed_entity.context.trust_marks()}
        else:
            args = {"trust_marks": _fed_entity.context.trust_marks}
    else:
        args = {}

    _ec = create_entity_statement(iss=_fed_entity.entity_id,
                                  sub=_fed_entity.entity_id,
                                  key_jar=_fed_entity.get_attribute('keyjar'),
                                  metadata=_metadata,
                                  authority_hints=_fed_entity.get_authority_hints(),
                                  **args
                                  )

    response = make_response(_ec)
    response.headers['Content-Type'] = 'application/jose; charset=UTF-8'
    return response


@entity.route('/rp')
def rp():
    link = request.args.get('iss', None)
    if not link:
        link = request.args.get('entity_id')

    if link:
        try:
            result = get_rph().begin(link)
        except Exception as err:
            logger.exception("RP begin")
            return make_response('Something went wrong:{}'.format(err), 400)
        else:
            return redirect(result, 303)
    else:
        _providers = list(get_rph().client_configs.keys())
        return render_template('rpe_opbyuid.html', providers=_providers)


def get_rp(op_hash):
    try:
        _iss = get_rph().hash2issuer[op_hash]
    except KeyError:
        logger.error('Unkown issuer: {} not among {}'.format(
            op_hash, list(get_rph().hash2issuer.keys())))
        return make_response("Unknown hash: {}".format(op_hash), 400)
    else:
        try:
            rp = get_rph().issuer2rp[_iss]
        except KeyError:
            return make_response("Couldn't find client for {}".format(_iss), 400)

    return rp


def guess_rp(state):
    for _iss, _rp in get_rph().issuer2rp.items():
        _context = _rp.upstream_get("context")
        if _context.state.get_iss(request.args['state']):
            return _iss, _rp
    return None, None


def timestamp2local(timestamp):
    utc = datetime.utcfromtimestamp(timestamp)
    epoch = time.mktime(utc.timetuple())
    offset = datetime.fromtimestamp(epoch) - datetime.utcfromtimestamp(epoch)
    return utc + offset


def finalize(op_identifier, request_args):
    rp = get_rp(op_identifier)

    if hasattr(rp, 'status_code') and rp.status_code != 200:
        logger.error(rp.response[0].decode())
        return rp.response[0], rp.status_code

    _context = rp.get_context()
    session['client_id'] = _context.get('client_id')
    session['state'] = request_args.get('state')

    if session['state']:
        iss = _context.cstate.get_set(session['state'], claim=["iss"])['iss']
    else:
        return make_response('Unknown state', 400)

    session['session_state'] = request_args.get('session_state', '')

    logger.debug('Issuer: {}'.format(iss))

    try:
        res = rp.finalize(request_args)
    except OidcServiceError as excp:
        # replay attack prevention, is that code was already used before
        return excp.__str__(), 403
    except Exception as excp:
        raise excp

    if 'userinfo' in res:
        _context = rp.get_context()
        endpoints = {}
        for k, v in _context.provider_info.items():
            if k.endswith('_endpoint'):
                endp = k.replace('_', ' ')
                endp = endp.capitalize()
                endpoints[endp] = v

        kwargs = {}

        # Do I support session status checking ?
        _status_check_info = _context.add_on.get('status_check')
        if _status_check_info:
            # Does the OP support session status checking ?
            _chk_iframe = _context.get('provider_info').get('check_session_iframe')
            if _chk_iframe:
                kwargs['check_session_iframe'] = _chk_iframe
                kwargs["status_check_iframe"] = _status_check_info['rp_iframe_path']

        # Where to go if the user clicks on logout
        kwargs['logout_url'] = "{}/logout".format(_context.base_url)

        _fe = current_app.server["federation_entity"]
        op = rp.context.provider_info["issuer"]
        trust_anchor = list(_fe.context.trust_chain[op].keys())[0]
        trust_chain = _fe.context.trust_chain[op]
        trust_path = trust_chain.iss_path
        trust_path_expires = timestamp2local(trust_chain.exp)
        trust_marks = trust_chain.verified_chain[1].get("trust_marks", [])
        return render_template('rpe_opresult.html', endpoints=endpoints,
                               userinfo=res['userinfo'],
                               access_token=res['token'],
                               id_token=res["id_token"],
                               trust_path=trust_path,
                               trust_path_expires=trust_path_expires,
                               trust_marks=trust_marks,
                               **kwargs)
    else:
        return make_response(res['error'], 400)


@entity.route('/authz_cb/<entity_id>')
def authz_cb(entity_id):
    return finalize(entity_id, request.args)


@entity.errorhandler(werkzeug.exceptions.BadRequest)
def handle_bad_request(e):
    return 'bad request!', 400


@entity.route('/repost_fragment')
def repost_fragment():
    return 'repost_fragment'


@entity.route('/ihf_cb')
def ihf_cb(self, op_hash='', **kwargs):
    logger.debug('implicit_hybrid_flow kwargs: {}'.format(kwargs))
    return render_template('repost_fragment.html')
