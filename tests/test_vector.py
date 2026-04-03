import json

from cryptojwt.jwk.rsa import new_rsa_key

# Generate an RSA key pair for tests
_rsa_key = new_rsa_key()

_priv_jwk = _rsa_key.serialize(private=True)
_pub_jwk = _rsa_key.serialize(private=False)

# The tests expect JSON strings that are later json.loads(...)

json_rsa_priv_key = json.dumps(_priv_jwk)
json_rsa_pub_key = json.dumps(_pub_jwk)

# Header used in test_01_create.py, also as JSON string
test_header_rsa = json.dumps({"typ": "JWT", "alg": "RS256"})