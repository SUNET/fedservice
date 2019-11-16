import base64
import hashlib
import logging
import os
import re
from html import entities as htmlentitydefs
from time import localtime, strftime
from urllib.parse import parse_qs

import cherrypy
from jwkest import as_bytes

logger = logging.getLogger(__name__)


def handle_error():
    cherrypy.response.status = 500
    cherrypy.response.body = [
        b"<html><body>Sorry, an error occured</body></html>"
    ]


def get_symkey(link):
    md5 = hashlib.md5()
    md5.update(link.encode("utf-8"))
    return base64.b16encode(md5.digest()).decode("utf-8")


# this pattern matches substrings of reserved and non-ASCII characters
pattern = re.compile(r"[&<>\"\x80-\xff]+")

# create character map
entity_map = {}

for i in range(256):
    entity_map[chr(i)] = "&#%d;" % i


def compact(qsdict):
    res = {}
    for key, val in qsdict.items():
        if len(val) == 1:
            res[key] = val[0]
        else:
            res[key] = val
    return res


for entity, char in htmlentitydefs.entitydefs.items():
    if char in entity_map:
        entity_map[char] = "&%s;" % entity


def escape_entity(m, get=entity_map.get):
    return "".join(map(get, m.group()))


def escape(string):
    return pattern.sub(escape_entity, string)


def create_result_page(client, userinfo, token, state):
    """
    Display information from the Authentication.
    """
    element = ["<h2>You have successfully logged in!</h2>",
               "<dl><dt>Accesstoken</dt><dd>{}</dd>".format(token),
               "<h3>Endpoints</h3>"]

    _pi = client.service_context.provider_info

    for key, val in _pi.items():
        if key.endswith('endpoint'):
            text = str(val)
            endp = key.replace('_', ' ')
            endp = endp.capitalize()
            element.append(
                "<dt>{}</dt><dd>{}</dd>".format(endp, text))

    element.append('</dl>')
    element.append('<h3>User information</h3>')
    element.append('<dl>')
    for key, value in userinfo.items():
        element.append("<dt>" + escape(str(key)) + "</dt>")
        element.append("<dd>" + escape(str(value)) + "</dd>")
    element.append('</dl>')

    return "\n".join(element)


class Root(object):
    @cherrypy.expose
    def index(self):
        response = [
            '<html><head>',
            '<title>My OpenID Connect RP</title>',
            '<link rel="stylesheet" type="text/css" href="/static/theme.css">'
            '</head><body>'
            "<h1>Welcome to my OpenID Connect RP</h1>",
            '</body></html>'
        ]
        return '\n'.join(response)


class Consumer(Root):
    _cp_config = {'request.error_response': handle_error}

    def __init__(self, rph, html_home='.', static_dir='static'):
        self.rph = rph
        self.html_home = html_home
        self.static_dir = static_dir

    @cherrypy.expose
    def index(self, uid='', iss=''):
        issuer_id = ''
        if iss:
            issuer_id = iss
        elif uid:
            pass
        else:
            fname = os.path.join(self.html_home, 'opbyuid.html')
            return as_bytes(open(fname, 'r').read())

        if issuer_id or uid:
            if uid:
                args = {'user_id':uid}
            else:
                args = {}
            try:
                result = self.rph.begin(issuer_id, **args)
            except Exception as err:
                raise cherrypy.HTTPError(err)
            else:
                raise cherrypy.HTTPRedirect(result['url'])

    def get_rp(self, op_hash):
        try:
            _iss = self.rph.hash2issuer[op_hash]
        except KeyError:
            logger.error('Unkown issuer: {} not among {}'.format(
                op_hash, list(self.rph.hash2issuer.keys())))
            raise cherrypy.HTTPError(400, "Unknown hash: {}".format(op_hash))
        else:
            try:
                rp = self.rph.issuer2rp[_iss]
            except KeyError:
                raise cherrypy.HTTPError(
                    400, "Couldn't find client for {}".format(_iss))
        return rp

    @cherrypy.expose
    def acb(self, op_hash='', **kwargs):
        logger.debug('Callback kwargs: {}'.format(kwargs))

        rp = self.get_rp(op_hash)

        try:
            iss = rp.session_interface.get_iss(kwargs['state'])
        except KeyError:
            raise cherrypy.HTTPError(400, 'Unknown state')

        res = self.rph.finalize(iss, kwargs)

        if res:
            fid, statement = rp.service_context.trust_path
            _st = localtime(statement.exp)
            time_str = strftime('%a, %d %b %Y %H:%M:%S')
            res.update({'federation':fid, 'fe_expires':time_str})

            fname = os.path.join(self.html_home, 'opresult.html')
            _pre_html = open(fname, 'r').read()
            _html = _pre_html.format(
                result=create_result_page(rp, **res))
            return as_bytes(_html)
        else:
            raise cherrypy.HTTPError('Server error')

    def _cp_dispatch(self, vpath):
        # Only get here if vpath != None
        ent = cherrypy.request.remote.ip
        logger.info('ent:{}, vpath: {}'.format(ent, vpath))

        if vpath[0] in self.static_dir:
            return self
        elif len(vpath) == 1:
            a = vpath.pop(0)
            if a == 'rp':
                return self

        elif len(vpath) == 2:
            a = vpath.pop(0)
            b = vpath.pop(0)
            if a == 'rp':
                cherrypy.request.params['uid'] = b
                return self
            elif a == 'authz_cb':
                cherrypy.request.params['op_hash'] = b
                return self.acb
            elif a == 'ihf_cb':
                cherrypy.request.params['op_hash'] = b
                return self.implicit_hybrid_flow

        return self

    @cherrypy.expose
    def repost_fragment(self, **kwargs):
        logger.debug('repost_fragment kwargs: {}'.format(kwargs))
        args = compact(parse_qs(kwargs['url_fragment']))
        op_hash = kwargs['op_hash']

        rp = self.get_rp(op_hash)

        x = rp.service_context.state_db.get_state(args['state'])
        logger.debug('State info: {}'.format(x))
        res = self.rph.finalize(x['as'], args)

        if res:
            fname = os.path.join(self.html_home, 'opresult.html')
            _pre_html = open(fname, 'r').read()
            _html = _pre_html.format(result=create_result_page(**res))
            return as_bytes(_html)
        else:
            raise cherrypy.HTTPError(400, res[1])

    @cherrypy.expose
    def implicit_hybrid_flow(self, op_hash='', **kwargs):
        logger.debug('implicit_hybrid_flow kwargs: {}'.format(kwargs))
        return self._load_HTML_page_from_file("html/repost_fragment.html",
                                              op_hash)

    def _load_HTML_page_from_file(self, path, value):
        if not path.startswith("/"): # relative path
            # prepend the root package dir
            path = os.path.join(os.path.dirname(__file__), path)

        with open(path, "r") as f:
            txt = f.read()
            txt = txt % value
            return txt
