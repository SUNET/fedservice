#!/usr/bin/env python

import json

from fedservice.entity.function import PolicyError
from fedservice.entity.function.policy import combine
from fedservice.entity.function.policy import TrustChainPolicy

# comb_policy = combine(policyA, policyB)
# res = TrustChainPolicy(None).apply_policy(RP_metadata, comb_policy)

def compare(singleton, array):
    if len(array) == 1:
        if singleton == array[0]:
            return True
    return False


def compare_dict(data1, data2):
    if data1.keys() == data2.keys():
        for key,val1 in data1.items():
            val2 = data2[key]
            if isinstance(val1, list):
                if isinstance(val2, list):
                    if set(val1) != set(val2):
                        return False
                else:
                    if compare(val2, val1) is False:
                        return False
            elif isinstance(val2, list):
                if compare(val1, val2) is False:
                    return False
            else:
                if val1 != val2:
                    return False
    return True

tests = json.loads(open("metadata-policy-test-vectors-2025-02-13.json").read())

for test in tests:
    if test["n"] == 1510:
        pass

    _error = None
    try:
        comb_policy = combine({"metadata_policy": test["TA"]}, {"metadata_policy": test["INT"]})
    except PolicyError as err:
        _error = test.get("error", None)
        if _error:
            # print(f"{err} ... {_error}")
            pass
        else:
            print(f"{test['n']} -> {err} [No combine]")
    else:
        _merged = test.get("merged", None)
        if _merged is None:
            if not "resolved" in test:
                print(f"{test['n']} => {comb_policy} [Should fail on merge]")
                continue

        # Now for applying to metadata

        if "metadata" not in test:
            print(f"{test['n']}: No test metadata")
        else:
            try:
                res = TrustChainPolicy(None).apply_policy(test["metadata"], comb_policy, protocol=None)
            except PolicyError as err:
                if "resolved" in test:
                    print(f"{test['n']} -> {err} $$$")
            else:
                if res:
                    _resolved = test.get("resolved", None)
                    if not _resolved:
                        print(f"{test['n']}: did not expect resolved metadata")
                    else:
                        if compare_dict(res, _resolved) is False:
                            print(f"{test['n']}: failed resolving metadata policy")
