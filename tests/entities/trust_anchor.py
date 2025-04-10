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
         subordinates: Optional[list] = None,
         endpoints: Optional[list] = None,
         key_config: Optional[dict] = None,
         services: Optional[list] = None,
         trust_mark_issuers: Optional[dict] = None,
         trust_mark_owners: Optional[dict] = None,
         ):
    if not endpoints:
        endpoints = TA_ENDPOINTS
    if not key_config:
        key_config = {"key_defs": DEFAULT_KEY_DEFS}
    if not services:
        services = ["entity_configuration", "entity_statement"]

    ta = make_federation_entity(
        entity_id,
        preference=preference,
        key_config=key_config,
        endpoints=endpoints,
        subordinate=subordinates,
        authority_hints=authority_hints,
        trust_anchors=trust_anchors,
        services=services,
        trust_mark_owners=trust_mark_owners,
        trust_mark_issuers=trust_mark_issuers
    )

    return ta
