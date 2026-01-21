import json
import os

from cryptojwt import KeyJar
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS

from fedservice.build_entity import FederationEntityBuilder

from fedservice.entity import FederationEntity
from idpyoidc.client.entity import Entity
from idpyoidc.key_import import import_jwks_as_json
from idpyoidc.node import Unit
from idpyoidc.server import Server

from fedservice.entity.function import tree2chains
from fedservice.entity.function import verify_self_signed_signature
from fedservice.entity.function.policy import TrustChainPolicy
from fedservice.entity.function.verifier import TrustChainVerifier
from fedservice.fetch_entity_statement.fs2 import FSPublisher
from tests.utils import DummyCollector

BASE_PATH = os.path.abspath(os.path.dirname(__file__))

jwks = open(os.path.join(BASE_PATH, 'base_data', 'feide.no', 'feide.no', 'jwks.json')).read()

ANCHOR = {'https://feide.no': json.loads(jwks)}

foodle_jwks = open(
    os.path.join(BASE_PATH, 'base_data', 'foodle.uninett.no', 'foodle.uninett.no', 'jwks.json')
).read()

ENTITY_ID = "https://anchor.example.com"

def test_eval_chains():
    # The Trust Anchor
    ENT = FederationEntityBuilder(
        ENTITY_ID,
        preference={
            "organization_name": "The example federation operator",
            "organization_uri": "https://ta.example.com",
            "contacts": "operations@ta.example.com"
        },
        key_conf={"key_defs": DEFAULT_KEY_DEFS}
    )
    ENT.add_endpoints()
    ENT.add_functions()
    ENT.add_services()

    entity = FederationEntity(**ENT.conf)

    target = 'https://foodle.uninett.no'
    foodle_key_jar = KeyJar()
    foodle_key_jar = import_jwks_as_json(foodle_key_jar, jwks, target)
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
    key_jar = import_jwks_as_json(key_jar, jwks, 'https://feide.no')

    _entity = FederationEntity(key_jar=key_jar)
    _entity.context.keyjar=key_jar
    _verifier = TrustChainVerifier(upstream_get=_entity.unit_get,
                                   trust_anchor=['https://feide.no'])

    trust_chains = _verifier(chains[0])
    assert len(trust_chains) == 1

    for trust_chain in trust_chains:
        assert trust_chain.anchor == "https://feide.no"

        _policy = TrustChainPolicy(upstream_get=_entity.unit_get)
        _policy(trust_chain)

        assert set(trust_chain.metadata.keys()) == {'openid_relying_party'}

        assert set(trust_chain.metadata['openid_relying_party'].keys()) == {
            'response_types', 'claims', 'contacts', 'application_type', 'redirect_uris',
            'id_token_signing_alg_values_supported', 'jwks_uri'}
