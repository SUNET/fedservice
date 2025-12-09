from typing import List
from typing import Optional

from idpyoidc.client.defaults import DEFAULT_KEY_DEFS

from fedservice.utils import make_federation_entity


def main(entity_id: str,
         authority_hints: Optional[List[str]] = None,
         trust_anchors: Optional[dict] = None,
         preference: Optional[dict] = None,
         endpoint: Optional[list] = None,
         key_config: Optional[dict] = None,
         trust_mark_entity: Optional[dict] = None,
         services: Optional[list] = None
         ):
    if preference is None:
        preference = {
            "organization_name": "The RP",
            "homepage_uri": "https://rp.example.com",
            "contacts": "operations@rp.example.com"
        }
    if not endpoint:
        endpoint = ["entity_configuration", "resolve"]
    if not key_config:
        key_config = {"key_defs": DEFAULT_KEY_DEFS}

    entity = make_federation_entity(
        entity_id=entity_id,
        preference=preference,
        authority_hints=authority_hints,
        endpoint=endpoint,
        key_config=key_config,
        trust_anchors=trust_anchors,
        httpc_params={
            "verify": False,
            "timeout": 14
        },
        trust_mark_entity=trust_mark_entity,
        services=services
    )

    return entity
