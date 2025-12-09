from typing import List
from typing import Optional
from typing import Union

from idpyoidc.client.defaults import DEFAULT_KEY_DEFS

from fedservice.utils import make_federation_entity


def main(entity_id: str,
         authority_hints: Optional[List[str]] = None,
         trust_anchors: Optional[dict] = None,
         preference: Optional[dict] = None,
         endpoint: Optional[list] = None,
         key_config: Optional[dict] = None,
         httpc_params: Optional[dict] = None,
         services: Optional[list] = None,
         functions: Optional[Union[list, dict]] = None,
         **kwargs
         ):
    if not endpoint:
        endpoint = ['entity_configuration', 'fetch', 'list']
    if not key_config:
        key_config = {"key_defs": DEFAULT_KEY_DEFS}
    if not httpc_params:
        httpc_params = {
            "verify": False,
            "timeout": 14
        }
    if not endpoint:
        endpoint = ["entity_configuration"]
    if not services:
        services = ["entity_configuration", "entity_statement"]

    entity = make_federation_entity(
        entity_id,
        preference=preference,
        key_config=key_config,
        authority_hints=authority_hints,
        endpoint=endpoint,
        trust_anchors=trust_anchors,
        httpc_params=httpc_params,
        functions=functions,
        services=services,
        **kwargs
    )
    return entity
