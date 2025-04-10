from urllib.parse import urlparse

import pytest
import responses
from cryptojwt.jws.jws import factory

from fedservice.defaults import federation_endpoints
from fedservice.defaults import federation_services
from fedservice.message import TrustMark
from fedservice.message import TrustMarkRequest
from tests import create_trust_chain_messages
from tests.build_federation import build_federation

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

TM_ID = "https://refeds.org/wp-content/uploads/2016/01/Sirtfi-1.0.pdf"
TA_ID = "https://anchor.example.com"

TA_ENDPOINTS = federation_endpoints("entity_configuration", "fetch", "list")
TA_SERVICES = federation_services("entity_configuration", "entity_statement", "trust_mark_status")

TRUST_MARK_ISSUER_ID = "https://tmi.example.com"

FEDERATION_CONFIG = {
    TA_ID: {
        "entity_type": "trust_anchor",
        "subordinates": [TRUST_MARK_ISSUER_ID],
        "kwargs": {
            "preference": {
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.org",
                "contacts": "operations@ta.example.org"
            },
            "endpoints": TA_ENDPOINTS,
            "services": TA_SERVICES,
        }
    },
    TRUST_MARK_ISSUER_ID: {
        "entity_type": "trust_mark_issuer",
        "trust_anchors": [TA_ID],
        "kwargs": {
            "preference": {
                "organization_name": "Trust Mark Issuer 'R US"
            },
            "authority_hints": [TA_ID],
            "trust_mark_entity": {
                "class": "fedservice.trust_mark_entity.entity.TrustMarkEntity",
                "kwargs": {
                    "trust_mark_specification": {
                        "https://refeds.org/sirtfi": {
                            "lifetime": 2592000
                        }
                    },
                    "trust_mark_db": {
                        "class": "fedservice.trust_mark_entity.FileDB",
                        "kwargs": {
                            "https://refeds.org/sirtfi": "sirtfi",
                        }
                    },
                    "endpoint": {
                        "trust_mark": {
                            "path": "trust_mark",
                            "class": "fedservice.trust_mark_entity.server.trust_mark.TrustMark",
                            "kwargs": {
                                "client_authn_method": [
                                    "private_key_jwt"
                                ],
                                "auth_signing_alg_values": [
                                    "ES256"
                                ]
                            }
                        },
                        "trust_mark_list": {
                            "path": "trust_mark_list",
                            "class":
                                "fedservice.trust_mark_entity.server.trust_mark_list.TrustMarkList",
                            "kwargs": {}
                        },
                        "trust_mark_status": {
                            "path": "trust_mark_status",
                            "class":
                                "fedservice.trust_mark_entity.server.trust_mark_status"
                                ".TrustMarkStatus",
                            "kwargs": {}
                        }
                    }
                }
            }
        }
    }
}


class TestSignedTrustMark():

    @pytest.fixture(autouse=True)
    def create_entities(self):
        self.federation_entity = build_federation(FEDERATION_CONFIG)
        self.ta = self.federation_entity[TA_ID]
        self.tmi = self.federation_entity[TRUST_MARK_ISSUER_ID]

    def test_create_trust_mark_self_signed(self):
        _endpoint = self.tmi.get_endpoint('trust_mark_status')
        _issuer = _endpoint.upstream_get("unit")
        _trust_mark = _issuer.self_signed_trust_mark(
            trust_mark_id='https://openid.net/certification',
            logo_uri=("http://openid.net/wordpress-content/uploads/2016/05/"
                      "oid-l-certification-mark-l-cmyk-150dpi-90mm.jpg")
        )

        # Unpack and verify the Trust Mark
        _mark = _issuer.unpack_trust_mark(_trust_mark)

        assert isinstance(_mark, TrustMark)
        assert _mark["trust_mark_id"] == "https://openid.net/certification"
        assert _mark['iss'] == _mark['sub']
        assert _mark['iss'] == self.tmi.entity_id
        assert set(_mark.keys()) == {'iss', 'sub', 'iat', 'trust_mark_id', 'logo_uri'}

    def test_create_unpack_trust_3rd_party(self):
        _sub = "https://op.ntnu.no"

        _tme = self.tmi.server.trust_mark_entity
        _trust_mark = _tme.create_trust_mark("https://refeds.org/sirtfi", _sub)
        _mark = _tme.unpack_trust_mark(_trust_mark, _sub)

        assert isinstance(_mark, TrustMark)

    def test_process_request(self):
        _sub = "https://op.ntnu.no"
        _endpoint = self.tmi.get_endpoint('trust_mark_status')
        _issuer = _endpoint.upstream_get("unit")
        _issuer.trust_mark_specification["https://refeds.org/sirtfi"] = {}
        _trust_mark = _issuer.create_trust_mark("https://refeds.org/sirtfi", _sub)

        resp = _endpoint.process_request({'trust_mark': _trust_mark})
        assert resp == {'response_args': {'active': True}}

    def test_request_response_mark(self):
        _sub = "https://op.ntnu.no"
        _endpoint = self.tmi.get_endpoint('trust_mark_status')
        _issuer = _endpoint.upstream_get("unit")
        _trust_mark = _issuer.create_trust_mark("https://refeds.org/sirtfi", _sub)

        _jws = factory(_trust_mark)
        _payload = _jws.jwt.payload()
        query = {"sub": _payload["sub"], "trust_mark_id": _payload["trust_mark_id"]}
        resp = self.tmi.get_endpoint('trust_mark_status').process_request(query)
        assert resp == {'response_args': {'active': True}}

    def test_request_response_args(self):
        # Create a Trust Mark
        _sub = "https://op.ntnu.no"
        _endpoint = self.tmi.get_endpoint('trust_mark_status')
        _issuer = _endpoint.upstream_get("unit")
        _trust_mark = _issuer.create_trust_mark("https://refeds.org/sirtfi", _sub)

        # Ask for a verification of the Trust Mark
        _jws = factory(_trust_mark)
        _payload = _jws.jwt.payload()

        tms = self.ta.get_service('trust_mark_status')
        req = tms.get_request_parameters(
            request_args={
                'sub': _payload['sub'],
                'trust_mark_id': _payload['trust_mark_id']
            },
            fetch_endpoint=self.tmi.get_endpoint('trust_mark_status').full_path
        )
        p = urlparse(req['url'])
        tmr = TrustMarkRequest().from_urlencoded(p.query)

        resp = self.tmi.get_endpoint('trust_mark_status').process_request(tmr.to_dict())
        assert resp == {'response_args': {'active': True}}

    def test_trust_mark_verifier(self):
        _endpoint = self.tmi.get_endpoint('trust_mark_status')
        _issuer = _endpoint.upstream_get("unit")
        _issuer.trust_mark_specification["https://refeds.org/sirtfi"] = {
            "ref": 'https://refeds.org/sirtfi'
        }

        _trust_mark = _issuer.create_trust_mark(id="https://refeds.org/sirtfi",
                                                sub=self.tmi.entity_id)

        where_and_what = create_trust_chain_messages(self.tmi, self.ta)

        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            verified_trust_mark = self.tmi.function.trust_mark_verifier(
                trust_mark=_trust_mark, trust_anchor=self.ta.entity_id)

        assert verified_trust_mark
        assert set(verified_trust_mark.keys()) == {'iat', 'iss', 'trust_mark_id', 'sub', 'ref'}

    def test_metadata(self):
        _metadata = self.tmi.get_metadata()
        assert "federation_entity" in _metadata
        assert set(_metadata["federation_entity"].keys()) == {'federation_resolve_endpoint',
                                                              'federation_trust_mark_endpoint',
                                                              'federation_trust_mark_list_endpoint',
                                                              'federation_trust_mark_status_endpoint',
                                                              'organization_name'}
        assert _metadata["federation_entity"]["federation_trust_mark_endpoint"] == 'https://tmi.example.com/trust_mark'
