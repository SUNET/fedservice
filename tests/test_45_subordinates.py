# AbstractFileSystem
import json
import os

import pytest
from idpyoidc.util import QPKey

from tests import rm_dir_files
from tests.build_federation import build_federation

BASE_PATH = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASE_PATH, local_file)


TA_ID = "https://trust_anchor.example.com"
RP_ID = "https://rp.example.com"

FEDERATION_CONFIG = {
    TA_ID: {
        "federation_entity": {
            "subordinate": {
                'class': 'idpyoidc.storage.abfile.AbstractFileSystem',
                'kwargs': {
                    'fdir': full_path('subordinate')
                }
            },
            "preference": {
                "organization_name": "The example federation operator",
                "organization_uri": "https://ta.example.org",
                "contacts": "operations@ta.example.org"
            },
            "endpoint": ['entity_configuration', 'list', 'fetch', 'resolve'],
        }
    },
    RP_ID: {
        "federation_entity": {
            "trust_anchors": [TA_ID],
            "authority_hints": [TA_ID],
            "preference": {
                "organization_name": "The example federation RP operator",
                "organization_uri": "https://rp.example.com",
                "contacts": "operations@rp.example.com"
            }
        },
        "openid_relying_party": {},
    }
}

class TestSubordinatePersistenceFileSystem(object):

    @pytest.fixture(autouse=True)
    def create_entities(self):
        _dir = full_path('subordinate')
        if os.path.exists(_dir):
            rm_dir_files(_dir)

        federation = build_federation(FEDERATION_CONFIG)
        self.ta = federation[TA_ID]
        self.rp = federation[RP_ID]

        _info = {
            "jwks": self.rp["federation_entity"].context.keyjar.export_jwks(),
            'authority_hints': [TA_ID]
        }

        fname = os.path.join(_dir, QPKey().serialize(RP_ID))
        with open(fname, 'w') as f:
            f.write(json.dumps(_info))

    def test_subordinate_list(self):
        _endpoint = self.ta.get_endpoint('list')
        _req = _endpoint.parse_request({})
        _resp_args = _endpoint.process_request(_req)
        assert _resp_args
        assert _resp_args['response_msg'] == f'["{self.rp.entity_id}"]'
        response = _endpoint.do_response(response_msg=_resp_args["response_msg"], request=_req)
        assert response
        assert response["response"] == '["https://rp.example.com"]'
        assert ('Content-type', 'application/json') in response["http_headers"]
