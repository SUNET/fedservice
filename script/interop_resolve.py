#!/usr/bin/env python3
import json

from cryptojwt.exception import BadSignature

from fedservice.entity.function import apply_policies
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import verify_trust_chains
from fedservice.entity.function.trust_chain_collector import verify_self_signed_signature
from fedservice.entity.function.trust_mark_verifier import TrustMarkVerifier
from fedservice.utils import make_federation_entity


def get_trust_anchor_info(trust_anchor) -> dict:
    federation_entity = make_federation_entity(entity_id="https://localhost", trust_anchors={})
    # federation_entity.keyjar.httpc_params = {"verify": False}

    _collector = federation_entity.get_function("trust_chain_collector")

    # Read the trust anchor entity configuration
    _jws = _collector.get_entity_configuration(trust_anchor)

    # Verify the self signed signature
    try:
        entity_configuration = verify_self_signed_signature(_jws)
    except BadSignature as err:
        print("Bad signature on TA self-signed entity configuration")
        print(_jws)
        exit(1)
    #
    return entity_configuration


def get_trust_chains(entity_id, trust_anchors):
    federation_entity = make_federation_entity(entity_id="https://localhost",
                                               trust_anchors=trust_anchors)
    #federation_entity.keyjar.httpc_params = {"verify": False}

    _ta = list(trust_anchors.keys())[0]
    chains, leaf_ec = collect_trust_chains(federation_entity, entity_id=entity_id, stop_at=_ta)
    if len(chains) == 0:
        print("No chains")

    trust_chains = verify_trust_chains(federation_entity, chains, leaf_ec)
    return apply_policies(federation_entity, trust_chains), federation_entity


if __name__ == '__main__':
    test_set = json.loads(open("resolve.json").read())

    for entity_id, anchors in test_set.items():
        for anchor in anchors:
            print(f"************ {entity_id} @ {anchor} ************")
            trust_anchor_entity_configuration = get_trust_anchor_info(anchor)

            # Now for collecting trust chain
            trust_anchors = {trust_anchor_entity_configuration["iss"]:
                                 trust_anchor_entity_configuration["jwks"]}

            trust_chains, federation_entity = get_trust_chains(entity_id=entity_id,
                                                               trust_anchors=trust_anchors)

            for trust_chain in trust_chains:
                print(20 * "=",
                      f" Trust Chain for: {entity_id} ending in {trust_chain.anchor} ",
                      20 * "=")
                trust_chain.verified_chain.reverse()
                for node in trust_chain.verified_chain:
                    if node["iss"] == node["sub"]:
                        print(20 * "-", f"Entity Configuration for: {node['iss']}", 20 * "-")
                    else:
                        if "trust_mark" in node:
                            print("'trust_mark' SHOULD NOT be used in a subordinate statement")
                        print(20 * "-",
                              f"Subordinate statement about: {node['sub']} from {node['iss']}",
                              20 * "-")
                    # print JSON
                    print(json.dumps(node, sort_keys=True, indent=2))

                print("== Metadata after metadata policy has been applied ==")
                print(json.dumps(trust_chain.metadata, sort_keys=True, indent=2))

                # Now verify trust marks
                trust_marks = trust_chain.verified_chain[0].get("trust_marks")
                if trust_marks:
                    ent = TrustMarkVerifier(federation_entity.upstream_get,
                                            federation_entity=federation_entity)
                    print("== TRUST MARKS ==")
                    for trust_mark in trust_marks:
                        res = ent(trust_mark["trust_mark"],
                                  trust_anchor_entity_configuration["iss"])
                        if res:
                            if res["trust_mark_id"] != trust_mark["trust_mark_id"]:
                                print("*** Mismatch in trust_mark_id ***")
                            print(res)
