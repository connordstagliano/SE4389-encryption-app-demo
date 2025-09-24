import json
import time
import secrets
from typing import Tuple

from encryption import b64e, b64d

class FileSessionStore:
    def __init__(self, file_path: str = 'sessions.json'):
        self.file_path = file_path
        self._data: dict[str, dict] = self._load()

    def _load(self) -> dict[str, dict]:
        try:
            with open(self.file_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def _save(self) -> None:
        with open(self.file_path, 'w') as f:
            json.dump(self._data, f, indent=2)

    def create(self, username: str, root_key: bytes, ttl_seconds: int = 3600) -> str:
        sid = secrets.token_urlsafe(24)
        now = int(time.time())

        self._data[sid] = {
            "username": username,
            "root_key": b64e(root_key),
            "exp": now + ttl_seconds,
        }
        self._save()

        return sid

    def get(self, sid: str) -> Tuple[str, bytes]:
        rec = self._data.get(sid)
        if not rec:
            self._data = self._load()
            rec = self._data.get(sid)

            if not rec:
                raise KeyError("session not found")

        if rec["exp"] < int(time.time()):
            self._data.pop(sid, None)
            self._save()
            raise KeyError("session expired")

        return rec["username"], b64d(rec["root_key"])

    def delete(self, sid: str) -> None:
        if sid in self._data:
            self._data.pop(sid, None)
            self._save()

    def purge_expired(self) -> int:
        now = int(time.time())
        expired = [k for k, v in self._data.items() if v.get("exp", 0) < now]

        for k in expired:
            self._data.pop(k, None)

        if expired:
            self._save()

        return len(expired)


