from typing import Optional


class TrustMarkContext(object):

    def __init__(self, client_authn_methods: Optional[dict] = None, **kwargs):
        self.client_authn_methods = client_authn_methods or {}
        self.trust_chain_cache = {}
        self.jti_db = {}
        self.upstream_get = kwargs.get("upstream_get", None)
        self.keyjar = None
