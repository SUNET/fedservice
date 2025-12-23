from cryptojwt import JWT
from cryptojwt import KeyJar
from cryptojwt.jwk.rsa import new_rsa_key

LEAF_ID = "https://credential_issuer.example.org"
INTERMEDIATE_ID = "https://intermediate.eidas.example.org"
TRUST_ANCHOR_ID = "https://trust-anchor.example.org"

LEAF_EC = {
    "metadata": {
        "openid_credential_issuer": {
            "jwks": {
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": "R2RzRXA0RVBydzFOVG1fdWRTMTZ3YTRmNnE1V3FfME1oMUZLekliY1NYOA",
                        "e": "AQAB",
                        "n": "5H_Xh7xgDWTxQVbJqmOGurokE8kr2e1KgMWcYOA74O_1PXd2ugjyIq9t1mVPSuwx-tySk2PKpjp--WrHn3A4UKJkuR11zhmdLBsU8TOBBu5MZ8atDujfRwILXdKsEXklvaB6PLT4zdZodgCs05Ky2e5sb5z6_CiDqgUVnWPmJLMkgpBtZ-kMd_lb9SooZllfUGlTksauJ2_gVQ-VpFUMXYjoJjNx97eukaYnREoCC3Ta_-8bcRoslx2xrIbu_UGVqipeN3NP-meff9VTZWYM3gmolwupnMCXXiikcR5USLVg0e_gz6OfoRVGKAWIpRRLTz2aiqukVHZdZX9tNmz0mw"
                    }
                ]
            }
        },
        "federation_entity": {
            "organization_name": "OpenID Credential Issuer example",
            "organization_uri": "https://credential_issuer.example.org/home",
            "policy_uri": "https://credential_issuer.example.org/policy",
            "logo_uri": "https://credential_issuer.example.org/static/logo.svg",
            "contacts": [
                "tech@credential_issuer.example.org"
            ]
        }
    },
    "authority_hints": [
        "https://intermediate.eidas.example.org"
    ]
}


TRUST_ANCHOR_EC = {
    "metadata": {
        "federation_entity": {
            "federation_fetch_endpoint": "https://trust-anchor.example.org/fetch",
            "federation_resolve_endpoint": "https://trust-anchor.example.org/resolve",
            "federation_list_endpoint": "https://trust-anchor.example.org/list",
            "organization_name": "TA example",
            "organization_uri": "https://trust-anchor.example.org/home",
            "policy_uri": "https://trust-anchor.example.org/policy",
            "logo_uri": "https://trust-anchor.example.org/static/logo.svg",
            "contacts": [
                "tech@trust-anchor.example.org"
            ]
        }
    },
    "constraints": {
        "max_path_length": 1
    }
}

# Construct the keys

LEAF_KEYJAR = KeyJar()
LEAF_KEYJAR.add_keys(issuer_id = LEAF_ID, keys = [new_rsa_key()])

INTERMEDIATE_KEYJAR = KeyJar()
INTERMEDIATE_KEYJAR.add_keys(issuer_id = INTERMEDIATE_ID, keys = [new_rsa_key()])

TRUST_ANCHOR_KEYJAR = KeyJar()
TRUST_ANCHOR_KEYJAR.add_keys(issuer_id = TRUST_ANCHOR_ID, keys = [new_rsa_key()])

# Leaf EC

_ec = LEAF_EC.copy()
_ec["jwks"] = LEAF_KEYJAR.export_jwks(issuer_id=LEAF_ID)
_ec["sub"] = LEAF_ID
_jwt = JWT(key_jar=INTERMEDIATE_KEYJAR, iss=INTERMEDIATE_ID)
_jwt.lifetime = 300000
_jws = _jwt.pack(_ec, jws_headers={"typ": "entity-statement+jwt"})
print(_jws)
print()

# Intermediate about leaf

_ec = {
    "sub": LEAF_ID,
    "jwks": LEAF_KEYJAR.export_jwks(issuer_id=LEAF_ID)
}
_jwt = JWT(key_jar=INTERMEDIATE_KEYJAR, iss=INTERMEDIATE_ID)
_jwt.lifetime = 300000
_jws = _jwt.pack(_ec, jws_headers={"typ": "entity-statement+jwt"})
print(_jws)
print()

# TA about intermediate

_ec = {
    "sub": INTERMEDIATE_ID,
    "jwks": INTERMEDIATE_KEYJAR.export_jwks(issuer_id=INTERMEDIATE_ID)
}
_jwt = JWT(key_jar=TRUST_ANCHOR_KEYJAR, iss=TRUST_ANCHOR_ID)
_jwt.lifetime = 300000
_jws = _jwt.pack(_ec, jws_headers={"typ": "entity-statement+jwt"})
print(_jws)
print()

# Create the Trust Anchor EC

_ec = TRUST_ANCHOR_EC.copy()
_ec["jwks"] = TRUST_ANCHOR_KEYJAR.export_jwks(issuer_id=TRUST_ANCHOR_ID)
_ec["sub"] = TRUST_ANCHOR_ID
_jwt = JWT(key_jar=TRUST_ANCHOR_KEYJAR, iss=TRUST_ANCHOR_ID)
_jwt.lifetime = 300000
_jws = _jwt.pack(_ec, jws_headers={"typ": "entity-statement+jwt"})
print(_jws)

