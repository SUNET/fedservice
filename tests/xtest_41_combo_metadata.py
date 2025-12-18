import json
import os

import pytest
from tests.build_entity import FederationEntityBuilder

from fedservice.defaults import LEAF_ENDPOINT
from fedservice.entity import FederationEntity

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

BASE_PATH = os.path.abspath(os.path.dirname(__file__))

jwks = open(os.path.join(BASE_PATH, 'base_data', 'feide.no', 'feide.no', 'jwks.json')).read()
ANCHOR = {'https://feide.no': json.loads(jwks)}

OPPONENT_ID = "https://example.org"
TENNANT_ID = "https://example.org/tennant1"
ENTITY_ID = "https://entity.example.org"
ISSUER = "https://example.org/adm1"


class TestFederationEntity(object):

    @pytest.fixture(autouse=True)
    def server_setup(self):
        ENT = FederationEntityBuilder(
            ENTITY_ID,
            metadata={
                "organization_name": "The example cooperation",
                "organization_uri": "https://www.example.com",
                "contacts": "operations@example.com"
            },
            key_conf={'key_defs': KEYDEFS}
        )
        ENT.add_services()
        ENT.add_functions()
        ENT.add_endpoints(metadata={"authority_hints": ['https://example.org']},
                          **LEAF_ENDPOINT)

        self.entity = FederationEntity(**ENT.conf)

    def test_metadata(self):
        metadata = self.entity.get_metadata()
        assert list(metadata.keys()) == ['federation_entity']
        assert set(metadata['federation_entity'].keys()) == {'organization_name',
                                                             'contacts',
                                                             'organization_uri'}

    def test_create_entity_configuration(self):
        _endpoint = self.entity.server.get_endpoint('entity_configuration')
        _req = _endpoint.parse_request({})
        _resp_args = _endpoint.process_request(_req)
        assert _resp_args
