import json

from cryptojwt import KeyJar
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import build_keyjar
import pytest

from fedservice.entity.function.trust_chain_collector import verify_self_signed_signature
from idpyoidc.key_import import import_jwks_as_json

from fedservice.entity_statement.create import create_entity_statement
from tests import test_vector

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

RECEIVER = 'https://example.org/op'
ISSUER_ID = "https://example.org"

@pytest.mark.parametrize(
    "alg",
    ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"],
)
def test_create_self_signed(alg):
    metadata = {
        "application_type": "web",
        "claims": [
            "sub",
            "name",
            "email",
            "picture"
        ],
        "id_token_signing_alg_values_supported": [
            "RS256",
            "RS512"
        ],
        "redirect_uris": [
            "https://foodle.uninett.no/callback"
        ],
        "response_types": [
            "code"
        ]
    }

    iss = ISSUER_ID
    sub = iss

    json_priv_key = json.loads(test_vector.json_rsa_priv_key)
    json_priv_key["alg"] = alg
    json_pub_key = json.loads(test_vector.json_rsa_pub_key)
    json_pub_key["alg"] = alg

    json_header_rsa = json.loads(test_vector.test_header_rsa)
    json_header_rsa["alg"] = alg

    sign_key_jar = KeyJar()
    _key = key_from_jwk_dict(json_priv_key)
    _key.add_kid()
    sign_key_jar.add_keys("", [_key])
    authority = ["https://ntnu.no"]

    _jwt = create_entity_statement(iss, sub, sign_key_jar, metadata=metadata,
                                   authority_hints=authority,
                                   signing_alg=alg)

    assert _jwt

    # _verifier = factory(_jwt)
    # verifier_key_jar = KeyJar()
    # verifier_key_jar.add_keys("", [key_from_jwk_dict(json_pub_key)])
    # res = _verifier.verify_compact(keys=keys)
    res = verify_self_signed_signature(_jwt)

    assert res
    assert res['iss'] == iss
    assert res['sub'] == sub
    assert set(res.keys()) == {'metadata', 'iss', 'exp', 'sub', 'iat',
                               'authority_hints', 'jwks'}


def test_signed_someone_else_metadata():
    metadata = {
        "application_type": "web",
        "claims": [
            "sub",
            "name",
            "email",
            "picture"
        ],
        "id_token_signing_alg_values_supported": [
            "RS256",
            "RS512"
        ],
        "redirect_uris": [
            "https://foodle.uninett.no/callback"
        ],
        "response_types": [
            "code"
        ]
    }

    iss = "https://example.com"
    sub = "https://foo.example.org/rp"

    sub_key_jar = build_keyjar(KEYSPEC, issuer_id=sub)

    iss_key_jar = build_keyjar(KEYSPEC, issuer_id=iss)

    iss_key_jar = import_jwks_as_json(iss_key_jar,
                                      sub_key_jar.export_jwks_as_json(issuer_id=sub),
                                      sub)

    sub_key_jar = import_jwks_as_json(sub_key_jar,
                                      iss_key_jar.export_jwks_as_json(issuer_id=iss),
                                      iss)

    authority = {"https://core.example.com": ["https://federation.example.org"]}

    _jwt = create_entity_statement(iss, sub, iss_key_jar, metadata=metadata,
                                   authority_hints=authority)

    assert _jwt

    _verifier = factory(_jwt)
    keys = sub_key_jar.get_jwt_verify_keys(_verifier.jwt)
    res = _verifier.verify_compact(keys=keys, sigalg="RS256")

    assert res
    assert res['iss'] == iss
    assert res['sub'] == sub
    assert set(res.keys()) == {'metadata', 'iss', 'exp', 'sub', 'iat',
                               'authority_hints', 'jwks'}
