import json
import os

from cryptojwt.jwt import utc_time_sans_frac

from fedservice.message import EntityStatement
from fedservice.message import SubordinateStatement
from fedservice.message import EntityConfiguration
from fedservice.message import FederationEntity
from fedservice.message import JWKSet
from fedservice.message import TrustMark
from fedservice.message import TrustMarkIssuers
from fedservice.message import TrustMarkOwners

BASE_PATH = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASE_PATH, local_file)


def test_subordinate_statement():
    file = full_path("document_examples/subordinate_statement_jwt.json")
    _data = json.loads(open(file, "r").read())
    _msg = SubordinateStatement().from_dict(_data)
    _now = utc_time_sans_frac()
    # Set expiration time to some time in the future
    _msg["exp"] = _now + 100
    _msg.verify()
    assert set(_msg["metadata"].keys()) == {"openid_provider", "oauth_client"}
    assert set(_msg["metadata_policy"].keys()) == {"openid_provider", "oauth_client"}


def test_trust_mark_owners():
    file = full_path("document_examples/trust_mark_owners.json")
    _data = json.loads(open(file, "r").read())
    _msg = TrustMarkOwners().from_dict(_data)
    _msg.verify()


def test_trust_entity_statement_comb():
    file = full_path("document_examples/trust_mark_issuers.json")
    _data = json.loads(open(file, "r").read())
    _msg = TrustMarkIssuers().from_dict(_data)
    _msg.verify()


def test_entity_statement_comb():
    file_1 = full_path("document_examples/entity_configuration_jwt.json")
    _data = json.loads(open(file_1, "r").read())
    file_2 = full_path("document_examples/trust_mark_owners.json")
    _data_2 = json.loads(open(file_2, "r").read())
    _data["trust_mark_owners"] = _data_2
    file_3 = full_path("document_examples/trust_mark_issuers.json")
    _data_3 = json.loads(open(file_3, "r").read())
    _data["trust_mark_issuers"] = _data_3

    _msg = EntityConfiguration().from_dict(_data)
    _now = utc_time_sans_frac()
    # Set expiration time to some time in the future
    _msg["exp"] = _now + 100
    _msg.verify()

    assert set(_msg["trust_mark_issuers"].keys()) == {"https://openid.net/certification/op",
                                                      "https://refeds.org/wp-content/uploads/2016/01/Sirtfi-1.0.pdf"}
    assert set(_msg["trust_mark_owners"].keys()) == {"https://refeds.org/wp-content/uploads/2016/01/Sirtfi-1.0.pdf"}
    assert _msg["trust_mark_owners"]["https://refeds.org/wp-content/uploads/2016/01/Sirtfi-1.0.pdf"]["sub"] == \
           "https://refeds.org/sirtfi"


def test_federation_entity():
    file = full_path("document_examples/federation_entity.json")
    _data = json.loads(open(file, "r").read())

    _msg = FederationEntity().from_dict(_data)

    assert set(_msg.keys()) == {'federation_fetch_endpoint',
                                'federation_list_endpoint',
                                'federation_trust_mark_list_endpoint',
                                'federation_trust_mark_status_endpoint',
                                'homepage_uri',
                                'organization_name'}


def test_oidc_rp():
    file = full_path("document_examples/oidc_rp.json")
    _data = json.loads(open(file, "r").read())

    _msg = FederationEntity().from_dict(_data)

    assert set(_msg.keys()) == {'iss', 'sub', 'iat', 'exp', 'metadata', 'jwks', 'authority_hints'}
    assert set(_msg['metadata'].keys()) == {'openid_relying_party'}
    assert set(_msg['metadata']['openid_relying_party'].keys()) == {'application_type',
                                                                    'client_registration_types',
                                                                    'grant_types',
                                                                    'jwks_uri',
                                                                    'logo_uri',
                                                                    'organization_name',
                                                                    'redirect_uris',
                                                                    'signed_jwks_uri'}


def test_oidc_op():
    file = full_path("document_examples/oidc_op.json")
    _data = json.loads(open(file, "r").read())

    _msg = FederationEntity().from_dict(_data)

    assert set(_msg.keys()) == {'iss', 'sub', 'iat', 'exp', 'metadata', 'jwks', 'authority_hints'}
    assert set(_msg['metadata'].keys()) == {'openid_provider'}
    assert set(_msg['metadata']['openid_provider'].keys()) == {'authorization_endpoint',
                                                               'client_registration_types_supported',
                                                               'federation_registration_endpoint',
                                                               'grant_types_supported',
                                                               'id_token_signing_alg_values_supported',
                                                               'issuer',
                                                               'logo_uri',
                                                               'op_policy_uri',
                                                               'pushed_authorization_request_endpoint',
                                                               'request_object_signing_alg_values_supported',
                                                               'response_types_supported',
                                                               'signed_jwks_uri',
                                                               'subject_types_supported',
                                                               'token_endpoint',
                                                               'token_endpoint_auth_methods_supported',
                                                               'token_endpoint_auth_signing_alg_values_supported'}


def test_JWKSet():
    file = full_path("document_examples/jwks_claim_set.json")
    _data = json.loads(open(file, "r").read())

    _msg = JWKSet().from_dict(_data)
    assert set(_msg.keys()) == {'iat', 'iss', 'sub', 'keys'}
    assert len(_msg["keys"]) == 2

def test_trust_mark():
    file = full_path("document_examples/trust_mark.json")
    _data = json.loads(open(file, "r").read())

    _msg = EntityStatement().from_dict(_data)
    assert set(_msg.keys()) == {'trust_marks', 'iss', 'iat', 'sub', 'exp', 'metadata'}
    assert len(_msg['trust_marks']) == 1

    # Set expiration time to some time in the future
    _now = utc_time_sans_frac()
    _msg["exp"] = _now + 100

    _msg.verify()

def test_trust_mark_delegation():
    file = full_path("document_examples/trust_mark_delegation.json")
    _data = json.loads(open(file, "r").read())

    _msg = TrustMark().from_dict(_data)
    assert set(_msg.keys()) == {'iat', 'trust_mark_type', 'delegation', 'exp', 'sub', 'iss'}

    # Set expiration time to some time in the future
    _now = utc_time_sans_frac()
    _msg["exp"] = _now + 100

    _msg.verify()
