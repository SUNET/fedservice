from typing import Optional
from typing import Union

from idpyoidc.client.service import Service
from idpyoidc.client.service_context import ServiceContext
from idpyoidc.message import Message

from fedservice.entity.function import get_federation_entity_keyjar
from fedservice.entity.utils import get_federation_entity


class FederationService(Service):
    application_protocol = ""

    def get_keyjar(self, context):
        return get_federation_entity_keyjar(context)

    def gather_verify_arguments(
            self,
            context: ServiceContext,
            response: Optional[Union[dict, Message]] = None,
            behaviour_args: Optional[dict] = None) -> dict:

        try:
            _iss = context.issuer
        except AttributeError:
            _iss = response['iss']

        kwargs = {"iss": _iss, "keyjar": get_federation_entity_keyjar(self), "verify": True}

        # Refer back to the client_id used in the auth request
        # That client_id might be different from the one used in requests at other times
        _cstate = getattr(context, "cstate", None)
        if _cstate and 'state' in response:
            _client_id = _cstate.get_claim(response["state"], "client_id")
            if _client_id:
                kwargs["client_id"] = _client_id

        if self.service_name == "provider_info":
            if context.issuer.startswith("http://"):
                kwargs["allow_http"] = True

        return kwargs
