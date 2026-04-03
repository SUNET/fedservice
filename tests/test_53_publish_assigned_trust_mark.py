import json
import os

from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import init_key_jar
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.client.defaults import DEFAULT_OIDC_SERVICES

from fedservice.defaults import DEFAULT_OIDC_FED_SERVICES
from fedservice.appclient import ClientEntity
from fedservice.utils import make_federation_combo
from fedservice.utils import make_federation_entity

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

SUB_KEYJAR = init_key_jar(key_defs=KEYDEFS)
BASE_PATH = os.path.abspath(os.path.dirname(__file__))

TRUST_MARKS = json.loads(open(os.path.join(BASE_PATH, "trust_marks.json")).read())

ENTITY_ID = "https://entity.example.org"
RP_ID = "https://rp.example.org"


def test_federation_entity_metadata():
    entity = make_federation_entity(
        ENTITY_ID,
        preference={
            "organization_name": "The leaf operator",
            "homepage_uri": "https://leaf.example.com",
            "contacts": "operations@leaf.example.com"
        },
        key_config={"uri_path": "static/fed_jwks.json", "key_defs": KEYDEFS},
        authority_hints=['https://ntnu.no'],
        endpoints=["entity_configuration"],
        trust_marks=TRUST_MARKS
    )

    metadata = entity.get_metadata()
    assert set(metadata.keys()) == {"federation_entity"}
    assert entity.context.trust_marks

    _endp = entity.get_endpoint("entity_configuration")
    res = _endp.process_request({})
    assert set(res.keys()) == {"response"}
    _jws = factory(res["response"])
    _payload = _jws.jwt.payload()
    assert "trust_marks" in _payload


def test_federation_combo_metadata():
    oidc_service = DEFAULT_OIDC_SERVICES.copy()
    oidc_service.update(DEFAULT_OIDC_FED_SERVICES)

    entity = make_federation_combo(
        ENTITY_ID,
        preference={
            "organization_name": "The leaf operator",
            "homepage_uri": "https://leaf.example.com",
            "contacts": "operations@leaf.example.com"
        },
        key_config={"uri_path": "static/fed_jwks.json", "key_defs": KEYDEFS},
        authority_hints=['https://ntnu.no'],
        endpoints=["entity_configuration"],
        trust_marks=TRUST_MARKS,
        entity_type={
            "openid_relying_party": {
                'class': ClientEntity,
                'kwargs': {
                    # OIDC core keys
                    "key_conf": {"uri_path": "static/jwks.json", "key_defs": DEFAULT_KEY_DEFS},
                    'config': {
                        'client_id': RP_ID,
                        'client_secret': 'a longesh password',
                        'redirect_uris': ['https://example.com/cli/authz_cb'],
                        "preference": {
                            "grant_types": ['authorization_code', 'implicit', 'refresh_token'],
                            "id_token_signed_response_alg": "ES256",
                            "token_endpoint_auth_method": "client_secret_basic",
                            "token_endpoint_auth_signing_alg": "ES256",
                            "client_registration_types": ["explicit"],
                        },
                    },
                    "services": oidc_service,
                    'client_type': 'oidc'
                }
            }
        }
    )

    metadata = entity.get_metadata()
    assert set(metadata.keys()) == {"openid_relying_party", "federation_entity"}
    assert entity["federation_entity"].context.trust_marks
    srv = entity["openid_relying_party"].get_service('registration')
    key_jar = entity['federation_entity'].keyjar
    jws = srv.create_entity_configuration(entity.entity_id, key_jar=key_jar)
    assert jws
    _jws = factory(jws)
    _payload = _jws.jwt.payload()
    assert "trust_marks" in _payload
