#!/usr/bin/env python3
import os
import sys

from cryptojwt.utils import importer
from fedservice.combo import FederationCombo
from flask.app import Flask
from idpyoidc.client.util import lower_or_upper
from idpyoidc.logging import configure_logging
from idpyoidc.ssl_context import create_context
from idpyoidc.util import load_config_file

from fedservice.utils import make_federation_combo

dir_path = os.path.dirname(os.path.realpath(__file__))

template_dir = os.path.join(dir_path, 'templates')


def init_app(dir_name, **kwargs) -> Flask:
    name = dir_name or __name__
    app = Flask(name, static_url_path='', **kwargs)
    sys.path.insert(0, dir_path)

    # Session key for the application session
    app.config['SECRET_KEY'] = os.urandom(12).hex()

    entity = importer(f"{dir_name}.views.entity")
    app.register_blueprint(entity)

    # Initialize the oidc_provider after views to be able to set correct urls
    app.cnf = load_config_file(f"{dir_name}/conf.json")
    app.cnf["cwd"] = dir_path
    app.server = make_federation_combo(**app.cnf["entity"])
    if isinstance(app.server, FederationCombo):
        app.federation_entity = app.server["federation_entity"]
    else:
        app.federation_entity = app.server

    return app


if __name__ == "__main__":
    print(sys.argv)
    directory_name = sys.argv[1]
    template_dir = os.path.join(dir_path, f'{directory_name}/templates')
    app = init_app(directory_name, template_folder=template_dir)
    if "logging" in app.cnf:
        configure_logging(config=app.cnf["logging"])
    _web_conf = app.cnf["webserver"]
    context = create_context(dir_path, _web_conf)
    _cert = "{}/{}".format(dir_path, lower_or_upper(_web_conf, "server_cert"))

    print('Listening on {}:{}'.format(_web_conf.get('domain'), _web_conf.get('port')))
    _trust_anchors = {k:v for k,v in app.federation_entity.context.trust_anchor.items()}
    print(f"Trust Anchors: {_trust_anchors}")
    # app.rph.federation_entity.collector.web_cert_path = _cert
    app.run(host=_web_conf.get('domain'), port=_web_conf.get('port'),
            debug=_web_conf.get("debug"), ssl_context=context)
