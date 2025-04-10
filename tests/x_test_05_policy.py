import pytest

from fedservice.entity.function import PolicyError
from fedservice.entity.function.policy import combine
from fedservice.entity.function.policy import combine_claim_policy
from fedservice.entity.function.policy import TrustChainPolicy

SIMPLE = [
    (
        "SUBSET_OF",
        {"subset_of": ['X', 'Y', 'Z']},
        {"subset_of": ['X', 'Y']},
        {"subset_of": ['X', 'Y']}),
    (
        "SUBSET_OF",
        {"subset_of": ['X', 'Y', 'Z']},
        {"subset_of": ['X', 'Y', 'W']},
        {"subset_of": ['X', 'Y']}
    ),
    (
        "SUBSET_OF",
        {"subset_of": ['A', 'X', 'Y', 'Z']},
        {"subset_of": ['X', 'Y', 'W']},
        {"subset_of": ['X', 'Y']}
    ),
    (
        "SUBSET_OF",
        {"subset_of": ['Y', 'Z']},
        {"subset_of": ['X', 'Y']},
        {"subset_of": ['Y']}
    ),
    (
        "SUBSET_OF",
        {"subset_of": ['X', 'Y']},
        {"subset_of": ['Z', 'Y']},
        {"subset_of": ['Y']}
    ),
    (
        "SUBSET_OF",
        {"subset_of": ['X', 'Y']},
        {"subset_of": ['Z', 'W']},
        PolicyError
    ),
    (
        "SUPERSET_OF",
        {"superset_of": ['X', 'Y', 'Z']},
        {"superset_of": ['X', 'Y']},
        {"superset_of": ['X', 'Y']}
    ),
    (
        "SUPERSET_OF",
        {"superset_of": ['X', 'Y', 'Z']},
        {"superset_of": ['X', 'Y', 'W']},
        {"superset_of": ['X', 'Y']}
    ),
    (
        "SUPERSET_OF",
        {"superset_of": ['A', 'X', 'Y', 'Z']},
        {"superset_of": ['X', 'Y', 'W']},
        {"superset_of": ['X', 'Y']}
    ),
    (
        "SUPERSET_OF",
        {"superset_of": ['Y', 'Z']},
        {"superset_of": ['X', 'Y']},
        {"superset_of": ['Y']}
    ),
    (
        "SUPERSET_OF",
        {"superset_of": ['X', 'Y']},
        {"superset_of": ['Z', 'Y']},
        {"superset_of": ['Y']}
    ),
    (
        "SUPERSET_OF",
        {"superset_of": ['X', 'Y']},
        {"superset_of": ['Z', 'W']},
        PolicyError
    ),

    (
        "ONE_OF",
        {"one_of": ['X', 'Y', 'Z']},
        {"one_of": ['X', 'Y']},
        {"one_of": ['X', 'Y']}
    ),
    (
        "ONE_OF",
        {"one_of": ['X', 'Y', 'Z']},
        {"one_of": ['X', 'Y', 'W']},
        {"one_of": ['X', 'Y']}
    ),
    (
        "ONE_OF",
        {"one_of": ['A', 'X', 'Y', 'Z']},
        {"one_of": ['X', 'Y', 'W']},
        {"one_of": ['X', 'Y']}
    ),
    (
        "ONE_OF",
        {"one_of": ['Y', 'Z']},
        {"one_of": ['X', 'Y']},
        {"one_of": ['Y']}
    ),
    (
        "ONE_OF",
        {"one_of": ['X', 'Y']},
        {"one_of": ['Z', 'Y']},
        {"one_of": ['Y']}
    ),
    (
        "ONE_OF",
        {"one_of": ['X', 'Y']},
        {"one_of": ['Z', 'W']},
        PolicyError
    ),
    (
        "ADD",
        {"add": "X"},
        {"add": "B"},
        {"add": ["X", "B"]}
    ),
    (
        "ADD",
        {"add": "X"},
        {"add": "X"},
        {"add": "X"}
    ),
    (
        "VALUE",
        {"value": "X"},
        {"value": "B"},
        PolicyError
    ),
    (
        "VALUE",
        {"value": "X"},
        {"value": "X"},
        {"value": "X"}
    ),
    (
        "VALUE",
        {"value": ["X", "Y"]},
        {"value": ["X", "Z"]},
        PolicyError
    ),
    (
        "DEFAULT",
        {"default": "X"},
        {"default": "B"},
        PolicyError
    ),
    (
        "DEFAULT",
        {"default": ["X", "B"]},
        {"default": ["B", "Y"]},
        PolicyError
    ),
    (
        "DEFAULT",
        {"default": "X"},
        {"default": "X"},
        {"default": "X"}
    ),
    (
        "ESSENTIAL",
        {"essential": True},
        {"essential": False},
        PolicyError
    ),
    (
        "ESSENTIAL",
        {"essential": False},
        {"essential": True},
        {"essential": True}
    ),
    (
        "ESSENTIAL",
        {"essential": True},
        {"essential": True},
        {"essential": True}
    ),
    (
        "ESSENTIAL",
        {"essential": False},
        {"essential": False},
        {"essential": False}
    )
]

COMPLEX = [
    (
        {"add": ['Z']},
        {"default": ['X', 'Y']},
        {"default": ['X', 'Y'], "add": ['Z']}
    ),
    (
        {"add": ['A']},
        {"essential": False},
        {"add": ['A'], "essential": False}
    ),
    (
        {"add": ['Z']},
        {"subset_of": ['X', 'Y']},
        PolicyError
    ),
    (
        {"add": ['X']},
        {"subset_of": ['X', 'Y']},
        {"subset_of": ['X', 'Y'], "add": ['X']}
    ),
    (
        {"add": ['Z']},
        {"superset_of": ['X', 'Y']},
        PolicyError
    ),
    (
        {"add": ['Z', "X", "Y"]},
        {"superset_of": ['X', 'Y']},
        {"superset_of": ['X', 'Y'], "add": ['Z', "X", "Y"]}
    ),
    (
        {"essential": False},
        {"default": 'A'},
        {"essential": False, "default": 'A'}
    ),
    (
        {"essential": True},
        {"default": 'A'},
        {"essential": True, "default": 'A'}
    ),
    (
        {"essential": False},
        {"value": 'A'},
        {"essential": False, "value": 'A'}
    ),
    (
        {"essential": True},
        {"value": 'A'},
        {"essential": True, "value": 'A'}
    ),
    (
        {"essential": False, "default": 'A'},
        {"default": 'A', "essential": True},
        {"essential": True, "default": 'A'}
    ),
    (
        {"essential": True, "default": 'A'},
        {"default": 'B', "essential": True},
        PolicyError
    ),
    (
        {"essential": False},
        {"subset_of": ['B']},
        {"essential": False, "subset_of": ['B']}
    ),
    (
        {"subset_of": ['X', 'Y', 'Z']},
        {"superset_of": ['Y', 'Z']},
        {"subset_of": ['X', 'Y', 'Z'], "superset_of": ['Y', 'Z']}
    ),
    (
        {"superset_of": ['Y', 'Z']},
        {"subset_of": ['X', 'Y']},
        PolicyError
    ),
    (
        {"subset_of": ['X', 'Y']},
        {"superset_of": ['X', 'Y']},
        {"subset_of": ['X', 'Y'], "superset_of": ['X', 'Y']}
    ),
    (
        {"superset_of": ['X', 'Y']},
        {"subset_of": ['X', 'Y']},
        {"subset_of": ['X', 'Y'], "superset_of": ['X', 'Y']}
    ),
    (
        {"subset_of": ['X', 'Y', 'Z']},
        {"superset_of": ['Y', 'A']},
        PolicyError
    ),
    (
        {"subset_of": ['X', 'Y', ]},
        {"superset_of": ['X', 'Y', 'A']},
        PolicyError
    ),
    (
        {"subset_of": ['X', 'Y']},
        {"default": ['X']},
        {"subset_of": ['X', 'Y'], "default": ['X']}
    ),
    (
        {"superset_of": ['X', 'Y']},
        {"default": ['X', 'Y', 'Z']},
        {"superset_of": ['X', 'Y'], "default": ['X', 'Y', 'Z']}
    ),
    (
        {"one_of": ['X', 'Y']},
        {"default": 'X'},
        {"one_of": ['X', 'Y'], "default": 'X'}
    ),
    (
        {"subset_of": ['X', 'Y']},
        {"default": ['X', 'Z']},
        PolicyError
    ),
    (
        {"subset_of": ['X', 'Y']},
        {"one_of": ['X', 'Y']},
        PolicyError
    ),
    (
        {"superset_of": ['X', 'Y']},
        {"default": ['X', 'Z']},
        PolicyError
    ),
    (
        {"one_of": ['X', 'Y']},
        {"default": 'Z'},
        PolicyError
    )
]


def assert_equal(val1, val2):
    assert set(val1.keys()) == set(val2.keys())

    for key, attr in val1.items():
        if isinstance(attr, bool):
            return attr == val2[key]
        elif isinstance(attr, list):
            return set(attr) == set(val2[key])
        else:
            return attr == val2[key]


@pytest.mark.parametrize("typ, superior, subordinate, result", SIMPLE)
def test_simple_policy_combinations(typ, superior, subordinate, result):
    if result in [PolicyError]:
        with pytest.raises(result):
            combine_claim_policy(superior, subordinate)
    else:
        cp = combine_claim_policy(superior, subordinate)
        assert assert_equal(cp, result)


@pytest.mark.parametrize("superior, subordinate, result", COMPLEX)
def test_complex_policy_combinations(superior, subordinate, result):
    if result in [PolicyError]:
        with pytest.raises(result):
            combine_claim_policy(superior, subordinate)
    else:
        cp = combine_claim_policy(superior, subordinate)
        assert assert_equal(cp, result)


FED = {
    "scopes": {
        "subset_of": ["openid", "eduperson", "phone"],
        "superset_of": ["openid"],
        "default": ["openid", "eduperson"]},
    "id_token_signed_response_alg": {
        "one_of": ["ES256", "ES384", "ES512"],
        "default": "ES256"
    },
    "contacts": {
        "add": "helpdesk@federation.example.org"},
    "application_type": {"value": "web"}
}

ORG = {
    "scopes": {
        "subset_of": ["openid", "eduperson", "address"],
        "default": ["openid", "eduperson"]},
    "id_token_signed_response_alg": {
        "one_of": ["ES256", "ES384"],
        "default": "ES256"},
    "contacts": {
        "add": "helpdesk@org.example.org"},
}

RES = {
    "scopes": {
        "subset_of": ["openid", "eduperson"],
        "superset_of": ["openid"],
        "default": ["openid", "eduperson"]},
    "id_token_signed_response_alg": {
        "one_of": ["ES256", "ES384"],
        "default": "ES256"},
    "contacts": {
        "add": ["helpdesk@federation.example.org",
                "helpdesk@org.example.org"]},
    "application_type": {
        "value": "web"}
}


def test_combine_policies():
    res = combine({'metadata_policy': FED, 'metadata': {}},
                  {'metadata_policy': ORG, 'metadata': {}})

    assert set(res['metadata_policy'].keys()) == set(RES.keys())

    for claim, policy in res['metadata_policy'].items():
        assert set(policy.keys()) == set(RES[claim].keys())
        assert assert_equal(policy, RES[claim])


RP = {
    "contacts": ["rp_admins@cs.example.com"],
    "redirect_uris": ["https://cs.example.com/rp1"],
    "response_types": ["code"]
}

FED1 = {
    "scopes": {
        "superset_of": ["openid", "eduperson"],
        "default": ["openid", "eduperson"]
    },
    "response_types": {
        "subset_of": ["code", "code id_token"]},
    "id_token_signed_response_alg": {
        "one_of": ["ES256", "ES384"],
        "default": "ES256"}
}

ORG1 = {
    "contacts": {
        "add": "helpdesk@example.com"},
    "logo_uri": {
        "one_of": ["https://example.com/logo_small.jpg",
                   "https://example.com/logo_big.jpg"],
        "default": "https://example.com/logo_small.jpg"
    },
    "policy_uri": {
        "value": "https://example.com/policy.html"},
    "tos_uri": {
        "value": "https://example.com/tos.html"}
}

RES1 = {
    "contacts": ["rp_admins@cs.example.com", "helpdesk@example.com"],
    "logo_uri": "https://example.com/logo_small.jpg",
    "policy_uri": "https://example.com/policy.html",
    "tos_uri": "https://example.com/tos.html",
    "scopes": ["openid", "eduperson"],
    "response_types": ["code"],
    "redirect_uris": ["https://cs.example.com/rp1"],
    "id_token_signed_response_alg": "ES256"
}


def test_apply_policies():
    comb_policy = combine({'metadata_policy': FED1, 'metadata': {}},
                          {'metadata_policy': ORG1, 'metadata': {}})

    res = TrustChainPolicy(None).apply_policy(RP, comb_policy)

    assert set(res.keys()) == set(RES1.keys())

    for claim, value in res.items():
        if isinstance(value, list):
            if isinstance(RES1[claim], list):
                assert set(value) == set(RES1[claim])
            else:
                assert set(value) == {RES1[claim]}
        else:
            if isinstance(RES1[claim], list):
                assert {value} == set(RES1[claim])
            else:
                assert value == RES1[claim]


@pytest.mark.parametrize("policy, metadata, result",
                         [
                             (
                                     [{
                                         'metadata': {'B': 123},
                                         'metadata_policy': {
                                             "A": {"subset_of": ['a', 'b']}
                                         }},
                                         {
                                             'metadata': {'C': 'foo'},
                                             'metadata_policy': {
                                                 "A": {"subset_of": ['a']}
                                             }
                                         }
                                     ],
                                     {
                                         "A": ['a', 'b', 'e'],
                                         "C": 'foo'
                                     },
                                     {
                                         'A': ['a'],
                                         'B': 123,
                                         'C': 'foo'
                                     }
                             )
                         ])
def test_combine_metadata_and_metadata_policy_OK(policy, metadata, result):
    comb_policy = policy[0]
    for pol in policy[1:]:
        comb_policy = combine(comb_policy, pol)

    res = TrustChainPolicy(None).apply_policy(metadata, comb_policy)
    assert res == result


# 1 a subordinate can not change something a superior has set
@pytest.mark.parametrize("policy",
                         [
                             [
                                 {
                                     'metadata': {'B': 123},
                                     'metadata_policy': {
                                         "A": {"subset_of": ['a', 'b']}
                                     }
                                 },
                                 {
                                     'metadata': {'B': 'foo'},
                                     'metadata_policy': {
                                         "A": {"subset_of": ['a']}
                                     }
                                 }
                             ],
                             [
                                 {
                                     'metadata': {'B': 123},
                                 },
                                 {
                                     'metadata_policy': {
                                         "B": {"subset_of": [12, 6]}
                                     }
                                 }
                             ]
                         ])
def test_combine_metadata_and_metadata_policy_NOT_OK(policy):
    with pytest.raises(PolicyError):
        comb_policy = combine(policy[0], policy[1])
        res = TrustChainPolicy(None).apply_policy({}, comb_policy)


POLICY_1 = {
    "scopes": {
        "superset_of": ["openid", "eduperson"],
        "subset_of": ["openid", "eduperson"]
    }
}

POLICY_2 = {
    "response_types": {
        "subset_of": ["code", "code id_token"],
        "superset_of": ["code", "code id_token"]
    }
}

ENT = {
    "contacts": ["rp_admins@cs.example.com"],
    "redirect_uris": ["https://cs.example.com/rp1"],
    "response_types": ["code", "code id_token", "id_token"],
    "scopes": ["openid", "eduperson", "email", "address"]
}


def test_set_equality():
    comb_policy = combine({'metadata_policy': POLICY_1, 'metadata': {}},
                          {'metadata_policy': POLICY_2, 'metadata': {}})

    res = TrustChainPolicy(None).apply_policy(ENT, comb_policy)

    assert set(res['scopes']) == {"openid", "eduperson"}
    assert set(res['response_types']) == {"code", "code id_token"}


# @pytest.mark.parametrize(
#     "policy, metadata, result",
#     [
#         (
#                 (
#                         [
#                             {
#                                 'metadata': {'B': ["b", "d"]},
#                                 'metadata_policy': {
#                                     "A": {"subset_of": ['a', 'b']}
#                                 }
#                             },
#                             {
#                                 'metadata': {'C': "c"},
#                                 'metadata_policy': {
#                                     "A": {"add": ['c']},
#                                     "B": {"subset_of": ["d"]}
#                                 }
#                             }
#                         ],
#                         {'B': ['d'], 'C': 'c', 'A': ['a', 'b']},
#                         {'A': ['a', 'b'], 'B': ['d'], 'C': 'c'},
#                 )
#
#         )
#     ])
# def test_combine_metadata_and_metadata_policy_OK(policy, metadata, result):
#     comb_policy = policy[0]
#     for pol in policy[1:]:
#         comb_policy = combine(comb_policy, pol)
#
#     res = TrustChainPolicy(None).apply_policy(metadata, comb_policy)
#     for key, val in res.items():
#         if isinstance(val, list):
#             assert set(val) == set(result[key])
#         else:
#             assert val == result[key]

def test_spec_examples():
    TA_policy = {
        "metadata_policy": {
            "openid_relying_party": {
                "grant_types": {
                    "default": [
                        "authorization_code"
                    ],
                    "subset_of": [
                        "authorization_code",
                        "refresh_token"
                    ],
                    "superset_of": [
                        "authorization_code"
                    ]
                },
                "token_endpoint_auth_method": {
                    "one_of": [
                        "private_key_jwt",
                        "self_signed_tls_client_auth"
                    ],
                    "essential": True
                },
                "token_endpoint_auth_signing_alg": {
                    "one_of": [
                        "PS256",
                        "ES256"
                    ]
                },
                "subject_type": {
                    "value": "pairwise"
                },
                "contacts": {
                    "add": [
                        "helpdesk@federation.example.org"
                    ]
                }
            }
        }
    }

    ORP_TA_policy = {
        "metadata_policy": TA_policy["metadata_policy"]["openid_relying_party"]
    }

    SUB_policy = {
        "metadata_policy": {
            "openid_relying_party": {
                "grant_types": {
                    "subset_of": [
                        "authorization_code"
                    ]
                },
                "token_endpoint_auth_method": {
                    "one_of": [
                        "self_signed_tls_client_auth"
                    ]
                },
                "contacts": {
                    "add": [
                        "helpdesk@org.example.org"
                    ]
                }
            }
        },
        "metadata": {
            "openid_relying_party": {
                "sector_identifier_uri": "https://org.example.org/sector-ids.json",
                "policy_uri": "https://org.example.org/policy.html"
            }
        }
    }

    ORP_SUB_policy = {
        "metadata_policy": SUB_policy["metadata_policy"]["openid_relying_party"],
        "metadata": SUB_policy["metadata"]["openid_relying_party"]
    }

    result_metadata_policy = {
        "grant_types": {
            "default": [
                "authorization_code"
            ],
            "superset_of": [
                "authorization_code"
            ],
            "subset_of": [
                "authorization_code"
            ]
        },
        "token_endpoint_auth_method": {
            "one_of": [
                "self_signed_tls_client_auth"
            ],
            "essential": True
        },
        "token_endpoint_auth_signing_alg": {
            "one_of": [
                "PS256",
                "ES256"
            ]
        },
        "subject_type": {
            "value": "pairwise"
        },
        "contacts": {
            "add": [
                "helpdesk@federation.example.org",
                "helpdesk@org.example.org"
            ]
        }
    }

    comb_policy = combine(ORP_TA_policy, ORP_SUB_policy)
    assert compare(comb_policy["metadata_policy"], result_metadata_policy)

    RP_metadata = {
        "redirect_uris": [
            "https://rp.example.org/callback"
        ],
        "response_types": [
            "code"
        ],
        "token_endpoint_auth_method": "self_signed_tls_client_auth",
        "contacts": [
            "rp_admins@rp.example.org"
        ]
    }

    result_metadata = {
        "redirect_uris": [
            "https://rp.example.org/callback"
        ],
        "grant_types": [
            "authorization_code"
        ],
        "response_types": ["code"],
        "token_endpoint_auth_method": "self_signed_tls_client_auth",
        "subject_type": "pairwise",
        "sector_identifier_uri": "https://org.example.org/sector-ids.json",
        "policy_uri": "https://org.example.org/policy.html",
        "contacts": [
            "rp_admins@rp.example.org",
            "helpdesk@federation.example.org",
            "helpdesk@org.example.org"
        ]
    }

    res = TrustChainPolicy(None).apply_policy(RP_metadata, comb_policy)
    assert compare(res, result_metadata)


def compare(a, b):
    if set(a.keys()) != set(b.keys()):
        print(set(a.keys()).difference(set(b.keys())))
        return False

    for k, v in a.items():
        o = b[k]
        if isinstance(v, dict):
            if compare(v, o) is False:
                return False
        elif isinstance(v, list):
            if set(v) != set(o):
                return False
        else:
            if v != o:
                return False
    return True


def pick_metadata_policy(entity_statement, entity_type):
    res = {}
    _mp = entity_statement.get("metadata_policy", None)
    if _mp:
        _emp = _mp.get(entity_type)
        if _emp:
            res["metadata_policy"] = _emp
    _ma = entity_statement.get("metadata", None)
    if _ma:
        _ema = _ma.get(entity_type)
        if _ema:
            res["metadata"] = _ema
    return res


def test_federation_policy_A_2():
    EC_UMU = {
        "authority_hints": [
            "https://umu.se"
        ],
        "exp": 1568397247,
        "iat": 1568310847,
        "iss": "https://op.umu.se",
        "sub": "https://op.umu.se",
        "jwks": {
            "keys": [
                {
                    "e": "AQAB",
                    "kid": "dEEtRjlzY3djcENuT01wOGxrZlkxb3RIQVJlMTY0...",
                    "kty": "RSA",
                    "n": "x97YKqc9Cs-DNtFrQ7_vhXoH9bwkDWW6En2jJ044yH..."
                }
            ]
        },
        "metadata": {
            "openid_provider": {
                "issuer": "https://op.umu.se/openid",
                "signed_jwks_uri": "https://op.umu.se/openid/jwks.jose",
                "authorization_endpoint":
                    "https://op.umu.se/openid/authorization",
                "client_registration_types_supported": [
                    "automatic",
                    "explicit"
                ],
                "request_parameter_supported": True,
                "grant_types_supported": [
                    "authorization_code",
                    "implicit",
                    "urn:ietf:params:oauth:grant-type:jwt-bearer"
                ],
                "id_token_signing_alg_values_supported": [
                    "ES256", "RS256"
                ],
                "logo_uri":
                    "https://www.umu.se/img/umu-logo-left-neg-SE.svg",
                "op_policy_uri":
                    "https://www.umu.se/en/website/legal-information/",
                "response_types_supported": [
                    "code",
                    "code id_token",
                    "token"
                ],
                "subject_types_supported": [
                    "pairwise",
                    "public"
                ],
                "token_endpoint": "https://op.umu.se/openid/token",
                "federation_registration_endpoint":
                    "https://op.umu.se/openid/fedreg",
                "token_endpoint_auth_methods_supported": [
                    "client_secret_post",
                    "client_secret_basic",
                    "client_secret_jwt",
                    "private_key_jwt"
                ]
            }
        }
    }

    SS_UMU_OP = {
        "exp": 1568397247,
        "iat": 1568310847,
        "iss": "https://umu.se",
        "sub": "https://op.umu.se",
        "source_endpoint": "https://umu.se/oidc/fedapi",
        "jwks": {
            "keys": [
                {
                    "e": "AQAB",
                    "kid": "dEEtRjlzY3djcENuT01wOGxrZlkxb3RIQVJlMTY0...",
                    "kty": "RSA",
                    "n": "x97YKqc9Cs-DNtFrQ7_vhXoH9bwkDWW6En2jJ044yH..."
                }
            ]
        },
        "metadata_policy": {
            "openid_provider": {
                "contacts": {
                    "add": [
                        "ops@swamid.se"
                    ]
                },
                "organization_name": {
                    "value": "University of Umeå"
                },
                "subject_types_supported": {
                    "value": [
                        "pairwise"
                    ]
                },
                "token_endpoint_auth_methods_supported": {
                    "default": [
                        "private_key_jwt"
                    ],
                    "subset_of": [
                        "private_key_jwt",
                        "client_secret_jwt"
                    ],
                    "superset_of": [
                        "private_key_jwt"
                    ]
                }
            }
        }
    }

    SS_SWAMID_UMU = {
        "exp": 1568397247,
        "iat": 1568310847,
        "iss": "https://swamid.se",
        "sub": "https://umu.se",
        "source_endpoint": "https://swamid.se/fedapi",
        "jwks": {
            "keys": [
                {
                    "e": "AQAB",
                    "kid": "endwNUZrNTJsX2NyQlp4bjhVcTFTTVltR2gxV2RV...",
                    "kty": "RSA",
                    "n": "vXdXzZwQo0hxRSmZEcDIsnpg-CMEkor50SOG-1XUlM..."
                }
            ]
        },
        "metadata_policy": {
            "openid_provider": {
                "id_token_signing_alg_values_supported": {
                    "subset_of": [
                        "RS256",
                        "ES256",
                        "ES384",
                        "ES512"
                    ]
                },
                "token_endpoint_auth_methods_supported": {
                    "subset_of": [
                        "client_secret_jwt",
                        "private_key_jwt"
                    ]
                },
                "userinfo_signing_alg_values_supported": {
                    "subset_of": [
                        "ES256",
                        "ES384",
                        "ES512"
                    ]
                }
            }
        }
    }

    SS_EDUGAIN_SWAMID = {
        "exp": 1568397247,
        "iat": 1568310847,
        "iss": "https://edugain.geant.org",
        "sub": "https://swamid.se",
        "source_endpoint": "https://edugain.geant.org/edugain/api",
        "jwks": {
            "keys": [
                {
                    "e": "AQAB",
                    "kid": "N1pQTzFxUXZ1RXVsUkVuMG5uMnVDSURGRVdhUzdO...",
                    "kty": "RSA",
                    "n": "3EQc6cR_GSBq9km9-WCHY_lWJZWkcn0M05TGtH6D9S..."
                }
            ]
        },
        "metadata_policy": {
            "openid_provider": {
                "contacts": {
                    "add": "ops@edugain.geant.org"
                }
            },
            "openid_relying_party": {
                "contacts": {
                    "add": "ops@edugain.geant.org"
                }
            }
        }
    }

    comb_policy = combine(pick_metadata_policy(SS_EDUGAIN_SWAMID, "openid_provider"),
                          pick_metadata_policy(SS_SWAMID_UMU, "openid_provider"))
    comb_policy = combine(comb_policy,
                          pick_metadata_policy(SS_UMU_OP, "openid_provider"))

    # {'claims_parameter_supported', 'require_request_uri_registration', 'request_uri_parameter_supported'}

    VER_METADATA = {
        "authorization_endpoint":
            "https://op.umu.se/openid/authorization",
        # "claims_parameter_supported": False,
        "contacts": ['ops@swamid.se', 'ops@edugain.geant.org'],
        "federation_registration_endpoint":
            "https://op.umu.se/openid/fedreg",
        "client_registration_types_supported": [
            "automatic",
            "explicit"
        ],
        "grant_types_supported": [
            "authorization_code",
            "implicit",
            "urn:ietf:params:oauth:grant-type:jwt-bearer"
        ],
        "id_token_signing_alg_values_supported": [
            "RS256",
            "ES256"
        ],
        "issuer": "https://op.umu.se/openid",
        "signed_jwks_uri": "https://op.umu.se/openid/jwks.jose",
        "logo_uri":
            "https://www.umu.se/img/umu-logo-left-neg-SE.svg",
        "organization_name": "University of Umeå",
        "op_policy_uri":
            "https://www.umu.se/en/website/legal-information/",
        "request_parameter_supported": True,
        # "request_uri_parameter_supported": True,
        # "require_request_uri_registration": True,
        "response_types_supported": [
            "code",
            "code id_token",
            "token"
        ],
        "subject_types_supported": [
            "pairwise"
        ],
        "token_endpoint": "https://op.umu.se/openid/token",
        "token_endpoint_auth_methods_supported": [
            "private_key_jwt",
            "client_secret_jwt"
        ]
    }

    res = TrustChainPolicy(None).apply_policy(EC_UMU["metadata"]["openid_provider"], comb_policy)
    assert compare(res, VER_METADATA)
