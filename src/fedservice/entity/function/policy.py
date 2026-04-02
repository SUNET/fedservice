import logging
from typing import Optional

from fedservice.entity.function import Function
from fedservice.entity.function import PolicyError
from fedservice.entity.function.policy_operator import construct_evaluation_sequence
from fedservice.entity_statement.statement import TrustChain

logger = logging.getLogger(__name__)

COMBINATION = {
    "value": ["essential", "value"],
    "add": ["default", "subset_of", "superset_of", "essential", "add"],
    "default": ["add", "one_of", "subset_of", "superset_of", "essential", "default"],
    "one_of": ["default", "essential", "one_of"],
    "subset_of": ["add", "default", "superset_of", "essential", "subset_of"],
    "superset_of": ["add", "default", "subset_of", "essential", "superset_of"],
    # "essential": None
}


def combine_subset_of(sup, sub):
    if isinstance(sup, list):
        # if sup == []:  # ????
        #     if sub != []:
        #       raise PolicyError("Subordinates subset not subset of superior")
        res = set(sup)
    else:
        res = set()
        res.add(sup)

    return list(res.intersection(set(sub)))


def combine_superset_of(sup, sub):
    if sup == []:
        return sub
    elif set(sub).issuperset(set(sup)):
        return sub
    else:
        raise PolicyError("Subordinant's superset_of not superset of superior's superset_of")

def test_superset_of(s1, s2):
    sub = set(s2)
    if isinstance(s1, list):
        if s1 == []:  # ????
            return False
        sup = set(s1)
    else:
        sup = set()
        sup.add(s1)

    return sup.issuperset(sub)


def test_is_subset_of(s1, s2):
    if s2 == []:  # Nothing can be a subset of []
        return False

    sub = set(s2)
    if isinstance(s1, list):
        sup = set(s1)
    else:
        sup = set()
        sup.add(s1)

    return sup.issubset(sub)


def combine_one_of(s1, s2):
    if isinstance(s1, list):
        if s1 == []:  # ????
            return list(set(s2))
        sup = set(s1)
    else:
        sup = set()
        sup.add(s1)

    if sup.issubset(set(s2)):
        return list(set(s2))
    else:
        return []


def combine_add(s1, s2):
    if isinstance(s1, list):
        set1 = set(s1)
    else:
        set1 = {s1}
    if isinstance(s2, list):
        set2 = set(s2)
    else:
        set2 = {s2}
    return list(set1.union(set2))


POLICY_FUNCTIONS = {"subset_of", "superset_of", "one_of", "add", "value", "default", "essential"}

OP2FUNC = {
    "subset_of": combine_subset_of,
    "superset_of": combine_superset_of,
    "one_of": combine_one_of,
    "add": combine_add,
}


def do_sub_one_super_add(superior, child, policy):
    if policy in superior and policy in child:
        comb = OP2FUNC[policy](superior[policy], child[policy])
        #  if comb:
        return comb
        # else:
        #     raise PolicyError("Value sets doesn't overlap")
    elif policy in superior:
        return superior[policy]
    elif policy in child:
        return child[policy]


def do_value(superior, child, policy):
    if policy in superior and policy in child:
        if superior[policy] == child[policy]:
            return superior[policy]
        else:
            raise PolicyError("Not allowed to combine values")
    elif policy in superior:
        return superior[policy]
    elif policy in child:
        return child[policy]


def do_default(superior, child, policy):
    # A child's default can not override a superiors
    if policy in superior and policy in child:
        if superior[policy] == child[policy]:
            return superior[policy]
        else:
            raise PolicyError(f"Not allowed to change {policy}")
    elif policy in superior:
        return superior[policy]
    elif policy in child:
        return child[policy]


def do_essential(superior, child, policy):
    # essential: a child can make it True if a superior has states False
    # but not the other way around

    if policy in superior and policy in child:
        if not superior[policy] and child['essential']:
            return True
        else:
            return superior[policy]
    elif policy in superior:
        return superior[policy]
    elif policy in child:  # If the essential operator is omitted, this is equivalent to including it with a value of false.
        return child[policy]
    # else:
    #     return False


DO_POLICY = {
    "add": do_sub_one_super_add,
    "value": do_value,
    "superset_of": do_sub_one_super_add,
    "subset_of": do_sub_one_super_add,
    "one_of": do_sub_one_super_add,
    "default": do_default,
    "essential": do_essential
}


def _comb_value(superior, child):
    child_set = set(child).intersection(POLICY_FUNCTIONS)

    if "value" in child_set:
        if child["value"] != superior["value"]:  # Not OK
            raise PolicyError("Child can not set another value then superior")
        else:
            child_set.remove("value")
            del child["value"]
            if child_set:
                for key in child_set:
                    if key not in ["default", "essential"]:
                        raise PolicyError(f"{key} in subordinate")
            if child:
                superior.update(child)
            return superior

    for key in child_set:
        if key == "essential":
            if key in superior:
                if superior[key] == True and child[key] == False:
                    raise PolicyError(f"{key} mismatch")
                elif superior[key] == False and child[key] == True:
                    superior[key] = True
            else:
                superior[key] = child[key]
        elif key == "default":
            if key in superior:
                if superior[key] != child[key]:
                    raise PolicyError(f"{key} mismatch")
            else:
                superior[key] = child[key]
        elif key == "superset_of":
            if key in superior:
                _sup_set = combine_superset_of(superior[key], child[key])
                if _sup_set:
                    if superior["value"] not in _sup_set:
                        raise PolicyError(f"value ({superior['value']}) not in superset_of: ({_sup_set})")
                    superior[key] = _sup_set
            else:
                if test_superset_of(superior["value"], child[key]) is False:
                    raise PolicyError(f"value ({superior['value']}) not superset_of: ({child[key]})")
        elif key == "one_of":
            if key in superior:
                _sup_set = combine_one_of(superior[key], child[key])
                if _sup_set:
                    if superior["value"] not in _sup_set:
                        raise PolicyError(f"value ({superior['value']}) not in one_of: ({_sup_set})")
                    superior[key] = _sup_set
            else:
                if combine_one_of(superior["value"], child[key]) == []:
                    raise PolicyError(f"value ({superior['value']}) not in one_of: ({child[key]})")
        elif key == "subset_of":
            if key in superior:
                _sup_set = combine_subset_of(superior[key], child[key])
                if _sup_set:
                    if superior["value"] not in _sup_set:
                        raise PolicyError(f"value ({superior['value']}) not in subset_of: ({_sup_set})")
                    superior[key] = _sup_set
            else:
                if combine_subset_of(superior["value"], child[key]) == []:
                    raise PolicyError(f"value ({superior['value']}) not in subset_of: ({child[key]})")
        else:
            raise PolicyError(f"{key} can not be combined with value")

    # else:
    #     raise PolicyError(
    #         f"Not allowed combination of policies: {superior} + {child}")

    superior.update(child)
    return superior


def can_be_combined(set1, set2):
    for op1 in set1:
        if op1 == "essential":
            continue
        for op2 in set2:
            if op2 not in COMBINATION[op1]:
                return False

    return True


def value_combination_check(value, policy):
    for op in ["add", "one_of", "subset_of", "superset_of", "essential"]:
        policy_val = policy.get(op)
        if policy_val is not None:
            if op == "add":
                if isinstance(value, list):
                    if isinstance(policy_val, list):
                        if set(policy_val).issubset(set(value)):
                            pass
                        else:
                            return False
            elif op == "one_of":
                if value not in policy_val:
                    return False
            elif op == "subset_of":
                if isinstance(value, list):
                    if set(value).issubset(set(policy_val)) is False:
                        return False
                else:
                    sv = set()
                    sv.add(value)
                    if sv.issubset(set(policy_val)) is False:
                        return False
            elif op == "superset_of":
                if isinstance(value, list) is False:
                    return False
                if set(value).issuperset(set(policy_val)) is False:
                    return False
            elif op == "essential":
                if policy_val is True and value is None:
                    return False

    return True


def combination_check(superior, child):
    value = superior.get("value", None)
    if value is not None:
        if value_combination_check(value, child):
            return True
    else:
        value = child.get("value", None)
        if value:
            if value_combination_check(value, superior):
                return True
    for one, two, typ in [("add", "subset_of", "sub"), ("subset_of", "superset_of", "super")]:
        if one in superior and two in child:
            if typ == "sub":
                if set(superior.get(one)).issubset(child.get(two)):
                    return True
            else:
                if set(superior.get(one)).issuperset(child.get(two)):
                    return True
        elif two in superior and one in child:
            if typ == "sub":
                if set(superior.get(one)).issubset(child.get(two)):
                    return True
            else:
                if set(superior.get(one)).issuperset(child.get(two)):
                    return True
    return False


def combine_claim_policy(superior, child):
    """
    Combine policy rules.
    Applying the child policy can only make the combined policy more restrictive.

    :param superior: Superior policy
    :param child: Intermediates policy
    """

    # weed out every operator I don't recognize
    superior_set = set(superior).intersection(POLICY_FUNCTIONS)
    child_set = set(child).intersection(POLICY_FUNCTIONS)

    if can_be_combined(superior_set, child_set) is False:
        if combination_check(superior, child) is False:
            raise PolicyError(f"Illegal operator combination")

    if "value" in superior_set:  # An exact value can not be restricted.
        _sup_value = superior.get("value", None)
        _child_value = child.get("value", None)
        _sup_essential = superior.get("essential", None)
        _child_essential = child.get("essential", None)

        # The superior value MUST be None if _sup_value is None
        rule = {"value": _sup_value}

        if _sup_essential is True:
            if _child_essential is True:
                rule["essential"] = _sup_essential
            elif _child_essential is False:
                raise PolicyError("Subordinate can not set essential to false is superior has set it to True")
            else:
                rule["essential"] = _sup_essential
        elif _sup_essential is False:
            if _child_essential is not None:
                rule["essential"] = _child_essential
        else:
            if _sup_value is None and _child_essential is True:
                raise PolicyError("Illegal value/essential combination")
            if _child_essential is not None:
                rule["essential"] = _child_essential

        if _child_value is not None:
            # if value in both then value must be equal
                if _child_value != _sup_value:
                    raise PolicyError("Can not combine two unequal values")

        _sup_default = superior.get("default", None)
        _child_default = child.get("default", None)
        if _sup_default is not None:
            if _child_default is not None:
                if _sup_default != _child_default:
                    raise PolicyError("Can not combine two unequal defaults")
            rule["default"] = _sup_default
        elif _child_default is not None:
            rule["default"] = _child_default

        return rule
    else:
        if "essential" in superior_set and "essential" in child_set:
            # can only go from False to True
            if superior["essential"] != child["essential"] and child["essential"] is False:
                raise PolicyError("Essential can not go from True to False")

        comb_policy = superior_set.union(child_set)
        comb_policy.discard('essential')

        if "one_of" in comb_policy:
            if "subset_of" in comb_policy or "superset_of" in comb_policy:
                raise PolicyError("one_of can not be combined with subset_of/superset_of")

        rule = {}
        # operators that appear in both policies
        for policy in comb_policy:
            rule[policy] = DO_POLICY[policy](superior, child, policy)

        if comb_policy == {'superset_of', 'subset_of'}:
            # make sure the superset_of is a superset of superset_of.
            if set(rule['superset_of']).difference(set(rule['subset_of'])):
                raise PolicyError('superset_of not a super set of subset_of')
        elif comb_policy == {'superset_of', 'value'}:
            # make sure the subset_of is a superset of value.
            if test_superset_of(rule['value'], rule['superset_of']) is False:
                raise PolicyError('value is not a super set of superset_of')
        elif comb_policy == {'subset_of', 'value'}:
            # make sure the value is a subset of subset_of.
            if test_is_subset_of(rule['value'], rule['subset_of']) is False:
                raise PolicyError('value is not a sub set of subset_of')
        elif comb_policy == {'subset_of', 'add'}:
            if rule["add"] == []:
                pass
            elif not set(rule['add']).issubset(set(rule['subset_of'])):
                raise PolicyError('"add" not a subset of "subset"')
    return rule


def combine_metadata(superior_metadata: dict, subordinate_metadata: dict) -> dict:
    sup_m_set = set(superior_metadata.keys())
    _metadata = superior_metadata
    if subordinate_metadata:
        chi_m_set = set(subordinate_metadata.keys())
        _overlap = chi_m_set.intersection(sup_m_set)
        if _overlap:
            for key in _overlap:
                if superior_metadata[key] != subordinate_metadata[key]:
                    raise PolicyError(
                        'A subordinate is not allowed to set a value different from the superiors')

        _metadata = superior_metadata.copy()
        _metadata.update(subordinate_metadata)

    return _metadata


def combine(superior: dict, subordinate: dict) -> dict:
    """

    :param superior: Dictionary with two keys metadata_policy and metadata
    :param subordinate: Dictionary with two keys metadata_policy and metadata
    :return:
    """

    # Policy metadata only applies to subordinate
    # _metadata = combine_metadata(superior.get('metadata', {}), subordinate.get('metadata', {}))
    # if _metadata:
    #     superior['metadata'] = _metadata

    # Now for metadata_policies
    _sup_policy = superior.get('metadata_policy', {})
    _sub_policy = subordinate.get('metadata_policy', {})
    if _sub_policy:
        super_set = set(_sup_policy.keys())
        child_set = set(subordinate['metadata_policy'].keys())

        _metadata_policy = {}
        # appears both in superior and child
        for claim in set(super_set).intersection(child_set):
            _metadata_policy[claim] = combine_claim_policy(_sup_policy[claim], _sub_policy[claim])

        # only in super
        for claim in super_set.difference(child_set):
            _metadata_policy[claim] = _sup_policy[claim]

        # only if child
        for claim in child_set.difference(super_set):
            _metadata_policy[claim] = _sub_policy[claim]

        superior['metadata_policy'] = _metadata_policy

    return superior


def op_place(operator_name, policy_operators, index):
    while True:
        operator = policy_operators[index]
        if operator.name == operator_name:
            return index
        index += 1
        if index >= len(policy_operators):
            break
    return None


def apply_metadata_policy(metadata, metadata_policy, policy_operators):
    """
    Apply a metadata policy to a metadata statement.
    """

    policy_set = set(metadata_policy.keys())
    # metadata_set = set(metadata.keys())

    # Metadata claims that there exists a policy for
    for claim in policy_set:
        #
        # value_set = False
        for operator in policy_operators:
            if operator.name in metadata_policy.get(claim, {}):
                # if operator.name == "value":
                #     value_set = True
                operator(claim, metadata, metadata_policy)

    return metadata


class TrustChainPolicy(Function):

    def __init__(self, upstream_get):
        Function.__init__(self, upstream_get)
        self.policy_operators = construct_evaluation_sequence()

    def gather_policies(self, chain, entity_type):
        """
        Gather and combine all the metadata policies that are defined in the trust chain
        :param chain: A list of Entity Statements
        :return: The combined metadata policy
        """

        _rule = {'metadata_policy': {}, 'metadata': {}}
        for _item in ['metadata_policy', 'metadata']:
            try:
                _rule[_item] = chain[0][_item][entity_type]
            except KeyError:
                pass

        for es in chain[1:]:
            _sub_policy = {'metadata_policy': {}, 'metadata': {}}
            for _item in ['metadata_policy', 'metadata']:
                try:
                    _sub_policy[_item] = es[_item][entity_type]
                except KeyError:
                    pass

            if _sub_policy == {'metadata_policy': {}, 'metadata': {}}:
                continue

            _overlap = set(_sub_policy['metadata_policy']).intersection(
                set(_sub_policy['metadata']))
            if _overlap:  # Not allowed
                raise PolicyError('Claim appearing both in metadata and metadata_policy not allowed')
            _rule = combine(_rule, _sub_policy)

        return _rule

    def apply_policy(self, metadata: dict, policy: dict, protocol: Optional[str] = "oidc") -> dict:
        """
        Apply a metadata policy on metadata

        :param metadata: Metadata statements
        :param policy: A dictionary with metadata and metadata_policy as keys
        :return: A metadata statement that adheres to a metadata policy
        """

        _metadata_policy = policy.get('metadata_policy', None)
        if _metadata_policy:
            metadata = apply_metadata_policy(metadata, _metadata_policy, self.policy_operators)

        _metadata = policy.get("metadata", None)
        if _metadata:
            # what's in metadata policy metadata overrides what's in leaf's metadata
            metadata.update(_metadata)
            metadata = _metadata

        # This is a protocol specific adjustment
        if protocol in ["oidc", "oauth2"]:
            return {k: v for k, v in metadata.items() if v != []}
        else:
            return metadata

    def _policy(self, trust_chain: TrustChain, entity_type: str):
        combined_policy = self.gather_policies(trust_chain.verified_chain[:-1], entity_type)
        logger.debug(f"Combined policy for '{entity_type}': {combined_policy}")
        try:
            # This should be the entity configuration
            metadata = trust_chain.verified_chain[-1]['metadata'][entity_type]
        except KeyError:
            return None
        else:
            # apply the combined metadata policies on the metadata
            trust_chain.combined_policy[entity_type] = combined_policy
            _metadata = self.apply_policy(metadata, combined_policy)
            logger.debug(f"After applied policy for '{entity_type}': {_metadata}")
            return _metadata

    def __call__(self, trust_chain: TrustChain, entity_type: Optional[str] = ''):
        """
        :param trust_chain: TrustChain instance
        :param entity_type: Which Entity Type the entity are
        """
        if len(trust_chain.verified_chain) > 1:
            if entity_type:
                trust_chain.metadata[entity_type] = self._policy(trust_chain, entity_type)
            else:
                # rotate through the different entity types this entity has
                for _type in trust_chain.verified_chain[-1]['metadata'].keys():
                    trust_chain.metadata[_type] = self._policy(trust_chain, _type)
        else:
            trust_chain.metadata = trust_chain.verified_chain[0]["metadata"][entity_type]
            trust_chain.combined_policy[entity_type] = {}


def diff2policy(new, old):
    res = {}
    for claim in set(new).intersection(set(old)):
        if new[claim] == old[claim]:
            continue
        else:
            res[claim] = {'value': new[claim]}

    for claim in set(new).difference(set(old)):
        if claim in ['contacts']:
            res[claim] = {'add': new[claim]}
        else:
            res[claim] = {'value': new[claim]}

    return res
