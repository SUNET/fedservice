from typing import List
from typing import Optional

from idpyoidc.client.defaults import DEFAULT_KEY_DEFS

from fedservice.defaults import DEFAULT_FEDERATION_ENTITY_ENDPOINTS
from fedservice.utils import make_federation_entity

TA_ENDPOINTS = DEFAULT_FEDERATION_ENTITY_ENDPOINTS.copy()


def main(entity_id: str,
         authority_hints: Optional[List[str]] = None,
         trust_anchors: Optional[dict] = None,
         preference: Optional[dict] = None,
         endpoint: Optional[list] = None,
         key_config: Optional[dict] = None,
         httpc_params: Optional[dict] = None):
    if not endpoint:
        endpoint = ['entity_configuration', 'fetch', 'list']
    if not key_config:
        key_config = {"key_defs": DEFAULT_KEY_DEFS}
    if not preference:
        preference = {
            "organization_name": "The organization",
            "homepage_uri": "https://example.com",
            "contacts": "operations@example.com"
        }
    if not httpc_params:
        httpc_params = {
            "verify": False,
            "timeout": 14
        }

    if not endpoint:
        endpoint = ["entity_configuration", "fetch", "list"]

    im = make_federation_entity(
        entity_id,
        preference=preference,
        key_config=key_config,
        authority_hints=authority_hints,
        endpoint=endpoint,
        trust_anchors=trust_anchors,
        httpc_params=httpc_params
    )
    return im
