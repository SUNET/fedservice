from fedservice.entity.function import PolicyError

POLICY_APPLICATION_ORDER = ['value', 'add', 'default', 'one_of', 'subset_of', 'superset_of', 'essential']


def union(val1, val2):
    if isinstance(val1, list):
        base = set(val1)
    else:
        base = {val1}

    if isinstance(val2, list):
        ext = set(val2)
    else:
        ext = {val2}
    return base.union(ext)


class PolicyOperator(object):
    name = ""
    default_next = ""

    def __init__(self, next=""):
        self.next = next or self.default_next

    def __call__(self, claim, metadata, metadata_policy):
        return self.next


class Value(PolicyOperator):
    name = "value"
    default_next = "essential"

    def __call__(self, claim, metadata, metadata_policy):
        if metadata_policy[claim][self.name] == None:
            if claim in metadata:
                del metadata[claim]
        else:
            # value overrides everything
            metadata[claim] = metadata_policy[claim][self.name]
        return self.next


class OneOf(PolicyOperator):
    name = "one_of"
    default_next = "essential"

    def __call__(self, claim, metadata, metadata_policy):
        if claim in metadata:
            if isinstance(metadata[claim], list):  # Should not be
                return None
            else:
                if metadata[claim] in metadata_policy[claim][self.name]:
                    pass
                else:
                    raise PolicyError(
                        f"{metadata[claim]} not among {metadata_policy[claim][self.name]}")
                return self.next


class Add(PolicyOperator):
    name = "add"
    default_next = "default"

    def __call__(self, claim, metadata, metadata_policy):
        if claim in metadata:
            for val in metadata_policy[claim][self.name]:
                # the metadata claim value must be a list otherwise append doesn't work
                if isinstance(metadata, list):
                    pass
                else:
                    metadata[claim] = [metadata[claim]]
                if val not in metadata[claim]:
                    metadata[claim].append(val)
        else:
            metadata[claim] = metadata_policy[claim][self.name]

class Default(PolicyOperator):
    name = "default"
    default_next = "one_of"

    def __call__(self, claim, metadata, metadata_policy):
        if claim not in metadata:
            metadata[claim] = metadata_policy[claim][self.name]


class SubsetOf(PolicyOperator):
    name = "subset_of"
    default_next = "superset_of"

    def __call__(self, claim, metadata, metadata_policy):
        if claim in metadata:
            if isinstance(metadata[claim], list):
                _val = set(metadata_policy[claim][self.name]).intersection(set(metadata[claim]))
            else:
                if metadata[claim] in metadata_policy[claim]:
                    _val = metadata[claim]
                else:
                    raise PolicyError(f"{metadata[claim]} not in allowed subset: {metadata_policy[claim]}")

            metadata[claim] = list(_val)


class SupersetOf(PolicyOperator):
    name = "superset_of"
    default_next = "essential"

    def __call__(self, claim, metadata, metadata_policy):
        if claim in metadata:
            if set(metadata_policy[claim][self.name]).difference(set(metadata[claim])):
                raise PolicyError(f"{metadata[claim]} not superset of {metadata_policy[claim][self.name]}")


class Essential(PolicyOperator):
    name = "essential"
    default_next = ""

    def __call__(self, claim, metadata, metadata_policy):
        if metadata.get(claim, None) is None:
            if metadata_policy[claim][self.name] == True:
                raise PolicyError(f"Essential value missing for {claim}")


POLICY_OPERATORS = {
    'value': Value,
    'add': Add,
    "default": Default,
    "one_of": OneOf,
    "subset_of": SubsetOf,
    "superset_of": SupersetOf,
    "essential": Essential
}


def construct_evaluation_sequence():
    return [POLICY_OPERATORS[name]() for name in POLICY_APPLICATION_ORDER]
