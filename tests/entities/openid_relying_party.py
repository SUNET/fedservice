from typing import List
from typing import Optional

from fedservice import defaults
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS

from fedservice.defaults import DEFAULT_OAUTH2_FED_SERVICES
from fedservice.defaults import DEFAULT_OIDC_FED_SERVICES
from fedservice.utils import make_federation_combo


def main(entity_id: str,
         authority_hints: Optional[List[str]] = None,
         trust_anchors: Optional[dict] = None,
         preference: Optional[dict] = None,
         endpoint: Optional[list] = None,
         services: Optional[dict] = None,
         key_config: Optional[dict] = None,
         federation_services: Optional[list] = None,
         entity_type_config: Optional[dict] = None):
    if not endpoint:
        endpoint = ["entity_configuration"]
    if not key_config:
        key_config = {"key_defs": DEFAULT_KEY_DEFS}
    if preference is None:
        preference = {
            "organization_name": "The RP",
            "homepage_uri": "https://rp.example.com",
            "contacts": "operations@rp.example.com"
        }
    if services is None:
        _services = defaults.federation_services("entity_configuration", "entity_statement")
        _services.update(DEFAULT_OIDC_FED_SERVICES)
        services = _services

    if entity_type_config is None:
        entity_type_config = {
            'redirect_uris': [f'{entity_id}/cli/authz_cb'],
            "keys": {"key_defs": DEFAULT_KEY_DEFS},
            "preference": {
                "grant_types": ['authorization_code', 'implicit', 'refresh_token'],
                "id_token_signed_response_alg": "ES256",
                "token_endpoint_auth_method": "client_secret_basic",
                "token_endpoint_auth_signing_alg": "ES256"
            }
        }

    entity = make_federation_combo(
        entity_id,
        key_config=key_config,
        preference=preference,
        authority_hints=authority_hints,
        endpoint=endpoint,
        services=federation_services,
        trust_anchors=trust_anchors,
        httpc_params={
            "verify": False,
            "timeout": 14
        },
        entity_type={
            "openid_relying_party": {
                'class': "fedservice.appclient.ClientEntity",
                'kwargs': {
                    'config': entity_type_config,
                    "services": services
                }
            }
        }
    )

    return entity
