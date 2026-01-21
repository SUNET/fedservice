import logging

from cryptojwt import JWT
from cryptojwt.jwt import utc_time_sans_frac
from idpyoidc.message import oidc
from idpyoidc.server.endpoint import Endpoint

from fedservice.entity.utils import get_federation_entity

logger = logging.getLogger(__name__)


class SignedJWKS(Endpoint):
    request_cls = oidc.Message
    response_format = "json"
    content_type = 'application/jwk-set+jwt'
    name = "signed_jwks"
    endpoint_name = 'signed_jwks_uri'

    def __init__(self, upstream_get, **kwargs):
        Endpoint.__init__(self, upstream_get, **kwargs)

    def process_request(self, request=None, **kwargs):
        _federation_entity = get_federation_entity(self)
        _payload = _federation_entity.context.keyjar.export_jwks()
        _payload['sub'] = _federation_entity.entity_id
        _payload['iat'] = utc_time_sans_frac()
        _jwt = JWT(key_jar=_federation_entity.context.keyjar, iss=_federation_entity.entity_id)
        _jws = _jwt.pack(payload=_payload, jws_headers={"typ": self.content_type})
        return {'response_msg': _jws}
