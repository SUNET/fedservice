import json
import os
from urllib.parse import urlparse

import pytest
import responses

from fedservice.entity.function import get_verified_trust_chains
from . import create_trust_chain_messages
from .build_federation import build_federation

BASE_PATH = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASE_PATH, local_file)


class TestRpService(object):

    @pytest.fixture(autouse=True)
    def rp_service_setup(self):
        _json_conf = open(full_path("nordunet.json"), "r").read()
        self.federation = build_federation(json.loads(_json_conf))

        self.foodle = self.federation["https://foodle.uninett.no"]
        self.ntnu_op = self.federation["https://op.ntnu.no"]
        self.swamid = self.federation["https://swamid.se"]
        self.feide = self.federation["https://feide.no"]
        self.ntnu = self.federation["https://ntnu.no"]
        self.umu = self.federation["https://umu.se"]

    def test_1(self):
        rp_fe = self.foodle["federation_entity"]
        _ec = rp_fe.get_service("entity_configuration")
        op = self.ntnu_op["federation_entity"]
        _info = _ec.get_request_parameters(entity_id=op.entity_id)
        assert set(_info.keys()) == {'method', 'url'}
        p = urlparse(_info['url'])
        assert p.scheme == 'https'
        assert p.netloc == 'op.ntnu.no'
        assert p.path == "/.well-known/openid-federation"

    def test_parse_discovery_response(self):
        _trust_chain_collector = self.foodle["federation_entity"].get_function("trust_chain_collector")

        _msgs = create_trust_chain_messages(self.ntnu_op, self.ntnu, self.feide)

        with responses.RequestsMock() as rsps:
            for _url, _jwks in _msgs.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            trust_chains = get_verified_trust_chains(self.foodle["federation_entity"],
                                                     self.ntnu_op["federation_entity"].entity_id)

        assert len(trust_chains) == 1
        trust_chain = trust_chains[0]
        assert trust_chain.anchor == 'https://feide.no'

        self.foodle["openid_relying_party"].context.issuer = self.ntnu_op["federation_entity"].entity_id
        self.foodle.apply_metadata(trust_chain.metadata)
        # _pi_service = self.foodle["openid_relying_party"].get_service("provider_info")
        # _pi_service.update_service_context(trust_chain.metadata["openid_provider"])
        # _context = _pi_service.upstream_get("context")
        # _context.server_metadata = EntityMetadata(trust_chain.metadata)

        _context = self.foodle["openid_relying_party"].context
        _context.map_supported_to_preferred(info=_context.server_metadata['openid_provider'])
        assert set(
            [k for k, v in _context.prefers().items() if v]) == {'application_type',
                                                                 'callback_uris',
                                                                 'client_registration_types',
                                                                 'default_max_age',
                                                                 'grant_types_supported',
                                                                 'id_token_signing_alg_values_supported',
                                                                 'jwks',
                                                                 'redirect_uris',
                                                                 'request_object_signing_alg_values_supported',
                                                                 'request_parameter_supported',
                                                                 'response_modes_supported',
                                                                 'response_types_supported',
                                                                 'scopes_supported',
                                                                 'subject_types_supported',
                                                                 'token_endpoint_auth_methods_supported',
                                                                 'token_endpoint_auth_signing_alg_values_supported',
                                                                 'userinfo_signing_alg_values_supported'}
        assert set(_context.server_metadata.keys()) == {"openid_provider", "federation_entity"}
