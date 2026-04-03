__author__ = 'Roland Hedberg'
__version__ = '5.3.0'

from typing import Optional

from cryptojwt import as_unicode
from cryptojwt.jws.jws import factory

from fedservice.entity_statement.statement import chains2dict


def save_trust_chains(federation_context, trust_chains):
    _tc_dict = chains2dict(trust_chains)
    if getattr(federation_context, "trust_chain", None) is None:
        federation_context.trust_chain = {}

    for ta, tc in _tc_dict.items():
        _ent = tc.iss_path[0]
        if _ent not in federation_context.trust_chain:
            federation_context.trust_chain[_ent] = {ta: tc}
        else:
            federation_context.trust_chain[_ent].update({ta: tc})


def get_trust_chain(federation_context, entity_id: str, trust_anchor: Optional[str] = ""):
    trust_info = federation_context.trust_chain.get(entity_id, "")
    if not trust_info:
        return None

    if trust_anchor:
        return trust_info.get(trust_anchor, None)
    else:
        return trust_info


def get_payload(self_signed_statement):
    _jws = as_unicode(self_signed_statement)
    _jwt = factory(_jws)
    return _jwt.jwt.payload()
