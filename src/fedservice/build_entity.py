from typing import Optional

from fedservice.defaults import DEFAULT_FEDERATION_ENTITY_FUNCTIONS
from fedservice.defaults import federation_endpoints
from fedservice.defaults import FEDERATION_ENTITY_SERVICES

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]


class FederationEntityBuilder():

    def __init__(self,
                 entity_id: Optional[str] = '',
                 **kwargs
                 ):
        self.conf = {"entity_id": entity_id}
        for attr in ['key_conf', 'preference', 'authority_hints']:
            _val = kwargs.get(attr)
            self.conf[attr] = _val

    def add_services(self,
                     preference: Optional[dict] = None,
                     args: Optional[dict] = None,
                     kwargs_spec: Optional[dict] = None,
                     **services):
        # services are used to send request to endpoints

        kwargs = {}
        if services:
            kwargs['services'] = services
        else:
            kwargs['services'] = FEDERATION_ENTITY_SERVICES

        if kwargs_spec:
            for key, val in kwargs_spec.items():
                if key in kwargs["services"]:
                    kwargs["services"][key]["kwargs"].update(val)

        if preference:
            kwargs['preference'] = {}

        if kwargs_spec:
            for key, val in kwargs_spec.items():
                if key in kwargs["services"]:
                    kwargs["services"][key]["kwargs"].update(val)

        self.conf['client'] = {
            'class': 'fedservice.entity.client.FederationClient',
            'kwargs': kwargs
        }

    def add_endpoints(self,
                      preference: Optional[dict] = None,
                      args: Optional[dict] = None,
                      kwargs_spec: Optional[dict] = None,
                      **endpoints):
        # endpoints are accessible to services. Accepts requests and returns responses.
        kwargs = {}
        if endpoints:
            kwargs['endpoint'] = endpoints
        else:
            kwargs['endpoint'] = federation_endpoints("entity_configuration", "fetch", "list")

        if kwargs_spec:
            for key, val in kwargs_spec.items():
                if key in kwargs["endpoint"]:
                    kwargs["endpoint"][key]["kwargs"].update(val)

        if preference:
            kwargs['preference'] = {}

        if args:
            for item_type, _kwargs in args.items():
                if item_type in kwargs["endpoint"]:
                    kwargs["endpoint"][item_type]["kwargs"].update(_kwargs)

        self.conf['server'] = {
            'class': 'fedservice.entity.server.FederationServerEntity',
            'kwargs': kwargs
        }

    def add_functions(self,
                      preference: Optional[dict] = None,
                      args: Optional[dict] = None,
                      kwargs_spec: Optional[dict] = None,
                      **functions):
        # functions perform higher level service (like trust chain collection) based on the
        # available services.
        kwargs = {}
        if functions:
            kwargs['functions'] = functions
        else:
            kwargs['functions'] = DEFAULT_FEDERATION_ENTITY_FUNCTIONS

        if kwargs_spec:
            for key, val in kwargs_spec.items():
                if key in kwargs["functions"]:
                    kwargs["functions"][key]["kwargs"].update(val)

        if preference:
            kwargs['preference'] = {}

        if kwargs_spec:
            for key, val in kwargs_spec.items():
                if key in kwargs["functions"]:
                    kwargs["functions"][key]["kwargs"].update(val)

        self.conf['function'] = {
            'class': 'idpyoidc.node.Collection',
            'kwargs': kwargs
        }

    def set_attr(self, section, what):
        self.conf[section]['kwargs'].update(what)


EntityClass = {
    'openid_relying_party': {
        'endpoint': 'idpyoidc.server.Server',
        'function': 'idpyoidc.node.Collection',
        'service': 'idpyoidc.client.oidc.RP'
    },
    'openid_provider': {
        'endpoint': 'idpyoidc.server.Server',
        'function': 'idpyoidc.node.Collection',
        'service': 'idpyoidc.client.oidc.RP'
    },
    'oauth_authorization_server': {
        'endpoint': 'idpyoidc.server.Server',
        'function': 'idpyoidc.node.Collection',
        'service': 'idpyoidc.client.oauth2.Client'
    },
    'oauth_client': {
        'endpoint': 'idpyoidc.server.Server',
        'function': 'idpyoidc.node.Collection',
        'service': 'idpyoidc.client.oauth2.Client'
    }
}


class EntityBuilder():

    def __init__(self,
                 entity_id,
                 entity_type,
                 **kwargs
                 ):
        self.conf = {"entity_id": entity_id}
        for attr in ['key_conf', 'preference']:
            _val = kwargs.get(attr)
            self.conf[attr] = _val

    def add_services(self,
                     preference: Optional[dict] = None,
                     args: Optional[dict] = None,
                     kwargs_spec: Optional[dict] = None,
                     **services):
        # services are used to send request to endpoints

        kwargs = {}
        if not services:
            return

        kwargs['services'] = services

        if kwargs_spec:
            for key, val in kwargs_spec.items():
                if key in kwargs["services"]:
                    kwargs["services"][key]["kwargs"].update(val)

        if preference:
            kwargs['preference'] = {}

        if kwargs_spec:
            for key, val in kwargs_spec.items():
                if key in kwargs["services"]:
                    kwargs["services"][key]["kwargs"].update(val)

        self.conf['client'] = {
            'class': 'fedservice.entity.client.FederationClient',
            'kwargs': kwargs
        }

    def add_endpoints(self,
                      preference: Optional[dict] = None,
                      args: Optional[dict] = None,
                      kwargs_spec: Optional[dict] = None,
                      **endpoints):
        # endpoints are accessible to services. Accepts requests and returns responses.
        if not endpoints:
            return

        kwargs = {'endpoint': endpoints}

        if kwargs_spec:
            for key, val in kwargs_spec.items():
                if key in kwargs["endpoint"]:
                    kwargs["endpoint"][key]["kwargs"].update(val)

        if preference:
            kwargs['preference'] = {}

        if args:
            for item_type, _kwargs in args.items():
                if item_type in kwargs["endpoint"]:
                    kwargs["endpoint"][item_type]["kwargs"].update(_kwargs)

        self.conf['server'] = {
            'class': 'fedservice.entity.server.FederationServerEntity',
            'kwargs': kwargs
        }

    def add_functions(self,
                      preference: Optional[dict] = None,
                      args: Optional[dict] = None,
                      kwargs_spec: Optional[dict] = None,
                      **functions):
        # functions perform higher level service based on the
        # available basic services.

        if not functions:
            return

        kwargs = {'functions': functions}

        if kwargs_spec:
            for key, val in kwargs_spec.items():
                if key in kwargs["functions"]:
                    kwargs["functions"][key]["kwargs"].update(val)

        if preference:
            kwargs['preference'] = {}

        if kwargs_spec:
            for key, val in kwargs_spec.items():
                if key in kwargs["functions"]:
                    kwargs["functions"][key]["kwargs"].update(val)

        self.conf['function'] = {
            'class': 'idpyoidc.node.Collection',
            'kwargs': kwargs
        }

    def set_attr(self, section, what):
        self.conf[section]['kwargs'].update(what)
