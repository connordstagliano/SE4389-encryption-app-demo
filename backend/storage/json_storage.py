import json
from typing import List, Optional

from entities.user_entity import User
from entities.credential_entity import Credential
from storage.abstract_storage import AbstractStorage

class JsonStorage(AbstractStorage):
    def __init__(self, file_path: str = 'db.json'):
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

    def save_user(self, user: User) -> None:
        self._data[user.username] = user.to_dict()
        self._save()

    def get_user(self, username: str) -> Optional[User]:
        d = self._data.get(username)
        return User.from_dict(d) if d else None

    def save_credential(self, username: str, credential: Credential) -> None:
        self._data[username]['credentials'].append(credential.to_dict())
        self._save()
    
    def get_credentials(self, username: str) -> List[Credential]:
        return [Credential.from_dict(d) for d in self._data[username]['credentials']]