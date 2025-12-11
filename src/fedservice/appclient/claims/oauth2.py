from typing import Optional

from idpyoidc.client.claims.oauth2 import Claims as OAUth_claims
from idpyoidc.client.claims.oauth2 import REGISTER2PREFERRED

from fedservice.message import OauthClientInformationResponse
from fedservice.message import OauthClientMetadata


class Claims(OAUth_claims):
    register2preferred = REGISTER2PREFERRED
    registration_response = OauthClientInformationResponse
    registration_request = OauthClientMetadata

    _supports = OAUth_claims._supports.copy()
    _supports.update({
        "signed_jwks_uri": None,
        'organization_name': None,
    })

    callback_path = {}

    callback_uris = ["redirect_uris"]

    def __init__(self, prefer: Optional[dict] = None, callback_path: Optional[dict] = None):
        OAUth_claims.__init__(self, prefer=prefer, callback_path=callback_path)
