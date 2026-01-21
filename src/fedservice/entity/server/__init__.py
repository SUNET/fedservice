# Server specific defaults and a basic Server class
import logging
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from fedservice.entity.context import FederationServerContext
from idpyoidc.context import OidcContext
from idpyoidc.server.client_authn import client_auth_setup
from idpyoidc.server.configure import ASConfiguration
from idpyoidc.server.configure import OPConfiguration
from idpyoidc.server.endpoint import Endpoint
from idpyoidc.server.endpoint_context import EndpointContext
from idpyoidc.server.util import build_endpoints
from idpyoidc.util import instantiate

from fedservice.server import ServerUnit

logger = logging.getLogger(__name__)


class FederationServerEntity(ServerUnit):
    name = 'federation_entity'
    parameter = {"endpoint": [Endpoint], "context": EndpointContext}

    def __init__(
            self,
            upstream_get: Callable,
            config: Optional[Union[dict, OPConfiguration, ASConfiguration]] = None,
            keyjar: Optional[KeyJar] = None,
            context: Optional[OidcContext] = None,
            entity_id: Optional[str] = "",
            endpoint: Optional[dict] = None,
            preference: Optional[dict] = None,
            # subordinate: Optional[dict] = None,
            # policy: Optional[dict] = None,
            httpc: Optional[object] = None,
            httpc_params: Optional[dict] = None,
            **kwargs
    ):
        if config is None:
            config = {}
        self.conf = config

        if not entity_id:
            entity_id = upstream_get('attribute', "entity_id")
        self.endpoint = build_endpoints(endpoint, upstream_get=self.unit_get, issuer=entity_id)

        ServerUnit.__init__(self, upstream_get=upstream_get, keyjar=keyjar, context=context,
                            config=self.conf, preference=preference)

        if context:
            self.context = context
        else:
            self.context = FederationServerContext(
                config=config,
                upstream_get=self.unit_get,
                entity_id=entity_id,
                preference=preference,
            )

        # self.context.do_add_on(endpoints=self.endpoint)

        self.setup_client_authn_methods(config, self.context)
        for endpoint_name, item in self.endpoint.items():
            item.unit_get = self.unit_get
            item.context = self.context

        self.policy = {}
        self.subordinate = {}
        self.keyjar = None

        # Initiate class instance to handle policies and subordinates
        for attr in ['policy', 'subordinate']:
            spec = kwargs.get(attr)
            if spec:
                if 'class' in spec:
                    _kwargs = spec["kwargs"].copy()
                    _kwargs.update({"server_get": self.unit_get})
                    setattr(self, attr, instantiate(spec["class"], **_kwargs))
                else:
                    setattr(self, attr, spec)

    def get_endpoints(self, *arg):
        return self.endpoint

    def get_endpoint(self, endpoint_name, *arg):
        try:
            return self.endpoint[endpoint_name]
        except KeyError:
            return None

    def get_context(self, *arg):
        return self.context

    def get_attribute(self, attr, *args):
        val = getattr(self, attr)
        if val:
            return val
        else:
            return self.upstream_get('attribute', attr)

    def get_server(self, *args):
        return self

    def setup_client_authn_methods(self, config, context):
        context.client_authn_methods = client_auth_setup(
            context, self.unit_get, self.conf.get("client_authn_methods")
        )

class Context(object):

    def __init__(self):
        self.client_authn_methods = {}

