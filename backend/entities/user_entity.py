from dataclasses import dataclass
from typing import List

from encryption import MasterRecord as MasterRecordDict
from entities.credential_entity import Credential

@dataclass
class User:
    username: str
    master_record: MasterRecordDict
    credentials: List[Credential] = None

    def __post_init__(self):
        if self.credentials is None:
            self.credentials = []

    @classmethod
    def from_dict(cls, d: dict) -> 'User':
        creds = [Credential.from_dict(c) for c in d.get('credentials', [])]
        return cls(username=d['username'], master_record=d['master_record'], credentials=creds)

    def to_dict(self) -> dict:
        return {
            'username': self.username,
            'master_record': self.master_record,
            'credentials': [c.to_dict() for c in self.credentials]
        }