import logging

from idpyoidc.client.exception import OtherError
from idpyoidc.client.oidc import authorization
from idpyoidc.exception import UnSupported
from idpyoidc.util import conf_get

from fedservice.appclient.oauth2.authorization import automatic_registration
from fedservice.appclient.oauth2.authorization import create_request
from fedservice.appclient.oauth2.authorization import use_authorization_endpoint
from fedservice.appclient.oauth2.authorization import use_pushed_authorization_endpoint

logger = logging.getLogger(__name__)

class Authorization(authorization.Authorization):

    def __init__(self, upstream_get, conf=None):
        authorization.Authorization.__init__(self, upstream_get=upstream_get, conf=conf)
        self.pre_construct.append(automatic_registration)
        self.post_construct.append(create_request)

        self._use_authorization_endpoint = use_authorization_endpoint
        self._use_pushed_authorization_endpoint = use_pushed_authorization_endpoint

