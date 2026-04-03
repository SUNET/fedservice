import pytest
from cryptojwt.jwk.hmac import SYMKey
from cryptojwt.jws.jws import JWS

from fedservice.entity.trust_marks_source import TrustMarksFromABFile

NOW = 1000
SIGNING_KEY = SYMKey(key=b"0123456789abcdef0123456789abcdef", kid="symm")


@pytest.fixture(autouse=True)
def fixed_now(monkeypatch):
    # TrustMarksFromABFile uses time.time() via its own module import
    monkeypatch.setattr("fedservice.entity.trust_marks_source.time.time", lambda: NOW)


def _make_trust_mark_jws(
    *,
    sub: str,
    iss: str,
    trust_mark_type: str,
    iat: int,
    exp: int | None = None,
) -> str:
    payload = {
        "sub": sub,
        "iss": iss,
        "trust_mark_type": trust_mark_type,
        "iat": iat,
    }
    if exp is not None:
        payload["exp"] = exp

    _jws = JWS(payload, alg="HS256")
    _compact = _jws.sign_compact(keys=[SIGNING_KEY])
    if isinstance(_compact, bytes):
        _compact = _compact.decode("utf-8")
    return _compact


def _store_tm(
    source: TrustMarksFromABFile,
    key: str,
    *,
    sub: str,
    iss: str,
    trust_mark_type: str,
    iat: int,
    exp: int | None = None,
    outer_trust_mark_type: str | None = None,
) -> str:
    _jws = _make_trust_mark_jws(
        sub=sub,
        iss=iss,
        trust_mark_type=trust_mark_type,
        iat=iat,
        exp=exp,
    )
    source.store[key] = {
        "trust_mark": _jws,
        "trust_mark_type": outer_trust_mark_type or trust_mark_type,
    }
    return _jws


def test_selects_newest_per_issuer_and_prefers_no_exp_on_iat_tie(tmp_path):
    source = TrustMarksFromABFile(str(tmp_path), log_summary=False)

    sub = "entity"
    tmt = "https://trust/type"
    iss_a = "https://issuer.example/a"
    iss_b = "https://issuer.example/b"

    _store_tm(source, "older", sub=sub, iss=iss_a, trust_mark_type=tmt, iat=800, exp=3_600)

    _jws_newer_expiring = _store_tm(
        source, "newer_expiring", sub=sub, iss=iss_a, trust_mark_type=tmt, iat=900, exp=1_200
    )
    _jws_newer_no_exp = _store_tm(source, "newer_no_exp", sub=sub, iss=iss_a, trust_mark_type=tmt, iat=900)

    _jws_other_issuer = _store_tm(
        source, "second_issuer", sub=sub, iss=iss_b, trust_mark_type=tmt, iat=850, exp=4_000
    )

    marks = source(entity_id=sub)

    # Output is sorted by (_tmt, _iss) when by_issuer=True
    assert marks == [
        {"trust_mark_type": tmt, "trust_mark": _jws_newer_no_exp},
        {"trust_mark_type": tmt, "trust_mark": _jws_other_issuer},
    ]
    assert _jws_newer_expiring != _jws_newer_no_exp


def test_groups_by_type_when_not_by_issuer(tmp_path):
    source = TrustMarksFromABFile(str(tmp_path), by_issuer=False, log_summary=False)

    sub = "entity"
    tmt = "https://trust/type"
    tmt_other = "https://trust/other"

    _jws_a = _store_tm(
        source, "issuer_a", sub=sub, iss="https://issuer.example/a", trust_mark_type=tmt, iat=800, exp=4000
    )
    _jws_b = _store_tm(
        source, "issuer_b", sub=sub, iss="https://issuer.example/b", trust_mark_type=tmt, iat=900, exp=4000
    )
    _jws_other = _store_tm(
        source, "issuer_b_other_type", sub=sub, iss="https://issuer.example/b", trust_mark_type=tmt_other, iat=850, exp=4000
    )

    marks = source(entity_id=sub)

    # Sorted by (_tmt, "") when by_issuer=False
    assert marks == [
        {"trust_mark_type": tmt_other, "trust_mark": _jws_other},
        {"trust_mark_type": tmt, "trust_mark": _jws_b},
    ]
    assert _jws_a != _jws_b


def test_filters_by_subject_and_time_constraints(tmp_path):
    source = TrustMarksFromABFile(str(tmp_path), log_summary=False, leeway=10)

    tmt = "https://trust/type"
    iss = "https://issuer.example/a"

    _jws_valid = _store_tm(
        source, "valid", sub="expected-sub", iss=iss, trust_mark_type=tmt, iat=950, exp=2_000
    )

    _store_tm(
        source, "wrong_sub", sub="other-sub", iss=iss, trust_mark_type=tmt, iat=960, exp=2_000
    )

    _store_tm(
        source, "future_iat", sub="expected-sub", iss=iss, trust_mark_type=tmt, iat=1_050, exp=2_000
    )

    _store_tm(
        source, "expired", sub="expected-sub", iss=iss, trust_mark_type=tmt, iat=930, exp=900
    )

    marks = source(entity_id="expected-sub")
    assert marks == [{"trust_mark_type": tmt, "trust_mark": _jws_valid}]


def test_rejects_outer_inner_type_mismatch(tmp_path):
    source = TrustMarksFromABFile(str(tmp_path), log_summary=False)

    _store_tm(
        source,
        "mismatch",
        sub="entity",
        iss="https://issuer.example/a",
        trust_mark_type="https://trust/type-inner",
        outer_trust_mark_type="https://trust/type-outer",
        iat=900,
        exp=2_000,
    )

    assert source(entity_id="entity") == []


def test_skips_malformed_trust_mark_value(tmp_path):
    source = TrustMarksFromABFile(str(tmp_path), log_summary=False)

    source.store["bad"] = {
        "trust_mark": "not-a-jws",
        "trust_mark_type": "https://trust/type",
    }

    assert source(entity_id="entity") == []
