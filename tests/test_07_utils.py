import json
import os

from cryptojwt import KeyJar

from fedservice.entity.function import tree2chains
from fedservice.entity.function.policy import TrustChainPolicy
from fedservice.entity.function.verifier import TrustChainVerifier
from fedservice.entity_statement.collect import verify_self_signed_signature
from fedservice.fetch_entity_statement.fs2 import FSPublisher
from fedservice.node import Unit
from tests.utils import DummyCollector

BASE_PATH = os.path.abspath(os.path.dirname(__file__))

jwks = open(os.path.join(BASE_PATH, 'base_data', 'feide.no', 'feide.no', 'jwks.json')).read()

ANCHOR = {'https://feide.no': json.loads(jwks)}

BASE_PATH = os.path.abspath(os.path.dirname(__file__))

foodle_jwks = open(
    os.path.join(BASE_PATH, 'base_data', 'foodle.uninett.no', 'foodle.uninett.no', 'jwks.json')
).read()


def test_eval_chains():
    target = 'https://foodle.uninett.no'
    foodle_key_jar = KeyJar()
    foodle_key_jar.import_jwks_as_json(jwks, target)
    collector = DummyCollector(trust_anchors=ANCHOR,
                               httpd=FSPublisher(os.path.join(BASE_PATH, 'base_data')),
                               root_dir=os.path.join(BASE_PATH, 'base_data'),
                               keyjar=foodle_key_jar
                               )
    entity_configuration = collector.get_entity_statement(target,
                                                          issuer=target,
                                                          subject=target)
    _config = verify_self_signed_signature(entity_configuration)
    assert _config

    tree = collector.collect_tree(_config['iss'], _config)
    _unit = {target: (entity_configuration, tree)}
    chains = tree2chains(_unit)

    key_jar = KeyJar()
    key_jar.import_jwks_as_json(jwks, 'https://feide.no')

    _unit = Unit(keyjar=key_jar)
    _verifier = TrustChainVerifier(upstream_get=_unit.unit_get)

    statement = _verifier(chains[0])

    assert statement.anchor == "https://feide.no"

    _policy = TrustChainPolicy(upstream_get=_unit.unit_get)
    _policy(statement)

    assert set(statement.metadata.keys()) == {'openid_relying_party'}

    assert set(statement.metadata['openid_relying_party'].keys()) == {
        'response_types', 'claims', 'contacts', 'application_type', 'redirect_uris',
        'id_token_signing_alg_values_supported', 'jwks_uri'}
