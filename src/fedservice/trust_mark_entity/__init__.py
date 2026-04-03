import json
import os
from typing import Optional

from cryptojwt.jwt import utc_time_sans_frac


class FileDB(object):

    def __init__(self, **kwargs):
        self.config = kwargs
        for trust_mark_type, file_name in self.config.items():
            if not os.path.exists(file_name):
                # Only need to touch it
                fp = open(file_name, "w")
                fp.close()

    def add(self, tm_info: dict):
        trust_mark_type = tm_info['trust_mark_type']
        # adds a line with info about a trust mark info to the end of a file
        with open(self.config[trust_mark_type], "a") as fp:
            fp.write(json.dumps(tm_info) + '\n')

    def _match(self, sub, iat, tmi):
        if sub == tmi["sub"]:
            if iat:
                if iat == tmi['iat']:
                    return True
            else:
                return True
        return False

    def find(self, trust_mark_type: str, sub: str, iat: Optional[int] = 0):
        with open(self.config[trust_mark_type], "r") as fp:
            # Get the last issued
            for line in reversed(list(fp)):
                _tmi = json.loads(line.rstrip())

                if 'exp' in _tmi:
                    now = utc_time_sans_frac()
                    if now > _tmi["exp"]:
                        return False

                if self._match(sub, iat, _tmi):
                    return True
        return False

    def __contains__(self, item):
        return item in self.config

    def id_keys(self):
        return self.config.keys()

    def dump(self):
        res = {}
        for entity_id in self.config.keys():
            res[entity_id] = []
            with open(self.config[entity_id], "r") as fp:
                for line in list(fp):
                    res[entity_id].append(line.rstrip())
        return res

    def dumps(self):
        return json.dumps(self.dump())

    def load(self, info):
        for entity_id in self.config.keys():
            with open(self.config[entity_id], "a") as fp:
                for tm_info in info[entity_id]:
                    fp.write(tm_info + '\n')

    def loads(self, str):
        self.load(json.loads(str))

    def list(self, trust_mark_type: str, sub: Optional[str] = ""):
        res = []
        try:
            with open(self.config[trust_mark_type], "r") as fp:
                # Get the last issued
                for line in reversed(list(fp)):
                    _tmi = json.loads(line.rstrip())
                    if _tmi["sub"] not in res:
                        if sub:
                            if _tmi["sub"] == sub:
                                res.append(_tmi["sub"])
                        else:
                            res.append(_tmi["sub"])
        except KeyError as err:
            pass

        return res


class SimpleDB(object):

    def __init__(self):
        self._db = {}

    def add(self, tm_info: dict):
        if tm_info['trust_mark_type'] in self._db:
            self._db[tm_info['trust_mark_type']].append({tm_info['sub']: tm_info})
        else:
            self._db[tm_info['trust_mark_type']] = {tm_info["sub"]: tm_info}

    def list(self, trust_mark_type, sub: Optional[str] = ""):
        if sub:
            if self._db[trust_mark_type].get(sub, None):
                return [sub]
        elif trust_mark_type in self._db:
            return self._db[trust_mark_type]

    def find(self, trust_mark_type, sub: str, iat: Optional[int] = 0) -> bool:
        _tmi = self._db[trust_mark_type].get(sub, None)
        if _tmi:
            if iat:
                if iat == _tmi["iat"]:
                    return True
            else:
                return True

        return False

    def keys(self):
        return self._db.keys()

    def __getitem__(self, item):
        return self._db[item]

    def dump(self):
        return self._db

    def dumps(self):
        return json.dumps(self._db)

    def load(self, info):
        self._db = info

    def loads(self, info):
        self._db = json.loads(info)
