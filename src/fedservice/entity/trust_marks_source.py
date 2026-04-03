import time
import logging
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from fedservice import get_payload
from fedservice import message
from idpyoidc.storage.abfile import AbstractFileSystem

logger = logging.getLogger(__name__)


class TrustMarksFromABFile:
    """
    Reads Trust Marks from an AbstractFileSystem (abfile) directory and returns:
        [{"trust_mark_type": "...", "trust_mark": "<JWS>"}, ...]

    Store values should be JSON objects and contain at least:
        {"trust_mark": "<JWS>"}

    Selection behaviour:
      - groups by (trust_mark_type, iss) if by_issuer=True, else by (trust_mark_type)
      - prefers newest iat
      - if iat ties, prefers non-expiring (exp missing) over expiring, else later exp wins
      - filters out expired marks and marks with iat too far in the future (leeway)
      - optional sub filtering (self.sub or entity_id argument)
    """

    def __init__(
        self,
        fdir: str,
        key_conv: str = "idpyoidc.util.Base64",
        value_conv: str = "idpyoidc.util.JSON",
        sub: Optional[str] = None,
        by_issuer: bool = True,
        leeway: int = 60,
        log_summary: bool = True,
    ):
        self.sub = sub
        self.by_issuer = by_issuer
        self.leeway = leeway
        self.log_summary = log_summary

        self.store = AbstractFileSystem(
            fdir=fdir,
            key_conv=key_conv,
            value_conv=value_conv,
        )

    def _dbg(self, msg: str):
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(msg)

    @staticmethod
    def _exp_rank(_x: Optional[int]) -> float:
        return float("inf") if _x is None else float(_x)

    def __call__(self, entity_id: Optional[str] = None) -> List[Dict[str, Any]]:
        _now = int(time.time())
        _expected_sub = self.sub or entity_id

        _best: Dict[Tuple[str, str], Dict[str, Any]] = {}
        _skipped = Counter()

        # NOTE: Pure AbstractFileSystem usage. If key_conv cannot deserialize a filename, this will raise.
        for _k, _v in self.store.items():
            _k_str = str(_k)

            _jws = _v.get("trust_mark")
            if not _jws:
                _skipped["missing_trust_mark"] += 1
                self._dbg(f"Skipping trust mark. reason=missing_trust_mark key={_k_str}")
                continue

            try:
                _payload = get_payload(_jws)
                _tm = message.TrustMark(**_payload)
            except Exception as err:
                _skipped["malformed"] += 1
                self._dbg(f"Skipping trust mark. reason=malformed key={_k_str} err={type(err).__name__}: {err}")
                continue

            _tmt = _tm.get("trust_mark_type")
            _iss = _tm.get("iss")
            _sub = _tm.get("sub")
            _iat = _tm.get("iat")
            _exp = _tm.get("exp")

            if not (_tmt and _iss and _sub) or _iat is None:
                _skipped["missing_required_claims"] += 1
                self._dbg(
                    f"Skipping trust mark. reason=missing_required_claims key={_k_str} iss={_iss} sub={_sub} "
                    f"trust_mark_type={_tmt} iat={_iat}"
                )
                continue

            _outer_tmt = _v.get("trust_mark_type")
            if _outer_tmt and _tmt and _outer_tmt != _tmt:
                _skipped["type_mismatch"] += 1
                self._dbg(
                    f"Skipping trust mark. reason=type_mismatch key={_k_str} outer={_outer_tmt} inner={_tmt} "
                    f"iss={_iss} sub={_sub}"
                )
                continue

            if _expected_sub and _sub != _expected_sub:
                _skipped["sub_mismatch"] += 1
                self._dbg(
                    f"Skipping trust mark. reason=sub_mismatch key={_k_str} iss={_iss} trust_mark_type={_tmt} "
                    f"sub={_sub} expected_sub={_expected_sub}"
                )
                continue

            try:
                _iat_i = int(_iat)
            except (ValueError, TypeError):
                _skipped["iat_not_int"] += 1
                self._dbg(
                    f"Skipping trust mark. reason=iat_not_int key={_k_str} iss={_iss} trust_mark_type={_tmt} iat={_iat}"
                )
                continue

            if _iat_i > (_now + int(self.leeway)):
                _skipped["iat_in_future"] += 1
                self._dbg(
                    f"Skipping trust mark. reason=iat_in_future key={_k_str} iss={_iss} trust_mark_type={_tmt} "
                    f"iat={_iat_i} now={_now} leeway={self.leeway}"
                )
                continue

            _exp_i: Optional[int] = None
            if _exp is not None:
                try:
                    _exp_i = int(_exp)
                except (ValueError, TypeError):
                    _skipped["exp_not_int"] += 1
                    self._dbg(
                        f"Skipping trust mark. reason=exp_not_int key={_k_str} iss={_iss} trust_mark_type={_tmt} exp={_exp}"
                    )
                    continue

                if _exp_i <= _now:
                    _skipped["expired"] += 1
                    self._dbg(
                        f"Skipping trust mark. reason=expired key={_k_str} iss={_iss} trust_mark_type={_tmt} "
                        f"exp={_exp_i} now={_now}"
                    )
                    continue

            _group = (_tmt, _iss) if self.by_issuer else (_tmt, "")
            _cur = _best.get(_group)

            if (
                _cur is None
                or _iat_i > _cur["_iat"]
                or (_iat_i == _cur["_iat"] and self._exp_rank(_exp_i) > self._exp_rank(_cur.get("_exp")))
            ):
                _best[_group] = {
                    "trust_mark_type": _tmt,
                    "trust_mark": _jws,
                    "_iat": _iat_i,
                    "_exp": _exp_i,
                }
            else:
                _skipped["older_duplicate"] += 1
                self._dbg(
                    f"Skipping trust mark. reason=older_duplicate key={_k_str} iss={_iss} trust_mark_type={_tmt} "
                    f"iat={_iat_i} exp={_exp_i} chosen_iat={_cur['_iat']} chosen_exp={_cur.get('_exp')}"
                )

        if self.log_summary and _skipped and logger.isEnabledFor(logging.DEBUG):
            self._dbg(f"Trust mark selection summary. skipped={dict(_skipped)}")

        _out: List[Dict[str, Any]] = []
        for _key in sorted(_best.keys()):
            _v = _best[_key]
            _out.append({"trust_mark_type": _v["trust_mark_type"], "trust_mark": _v["trust_mark"]})

        return _out
