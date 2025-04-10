import os

from cryptojwt.jwt import utc_time_sans_frac

from fedservice.trust_mark_entity import FileDB

BASE_PATH = os.path.abspath(os.path.dirname(__file__))


def test_add_and_find():
    file_name = os.path.join(BASE_PATH, 'sirtfi')
    try:
        os.unlink(file_name)
    except FileNotFoundError:
        pass

    _db = FileDB(**{
        "https://refeds.org/sirtfi": file_name
    })

    _db.add({
        'trust_mark_id': "https://refeds.org/sirtfi",
        "sub": "https://example.com",
        'iat': utc_time_sans_frac()}
    )

    res = _db.find(trust_mark_id="https://refeds.org/sirtfi", sub="https://example.com")
    assert res
