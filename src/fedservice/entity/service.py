from typing import Optional
from typing import Union

from idpyoidc.client.service import Service
from idpyoidc.message import Message

from fedservice.entity.utils import get_federation_entity


class FederationService(Service):
    application_protocol = ""

    def gather_verify_arguments(
            self,
            response: Optional[Union[dict, Message]] = None,
            behaviour_args: Optional[dict] = None) -> dict:

        _context = self.upstream_get("context")
        _federation_entity = get_federation_entity(self)
        if _federation_entity:
            _keyjar = _federation_entity.keyjar
        else:
            _keyjar = _context.keyjar

        kwargs = {
            "iss": _context.issuer,
            "keyjar": _keyjar,
            "verify": True
        }

        # Refer back to the client_id used in the auth request
        # That client_id might be different from the one used in requests at other times
        _cstate = getattr(_context,"cstate", None)
        if _cstate and 'state' in response:
            _client_id = _cstate.get_claim(response["state"], "client_id")
            if _client_id:
                kwargs["client_id"] = _client_id

        if self.service_name == "provider_info":
            if _context.issuer.startswith("http://"):
                kwargs["allow_http"] = True

        return kwargs

