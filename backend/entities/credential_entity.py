from dataclasses import dataclass, asdict
from typing import Optional

from encryption import CredentialRecord as CredentialRecordDict

@dataclass
class Credential:
    site: str
    account: str
    enc_blob: dict
    version: str = "taco-v1"
    dup_tag: Optional[str] = None

    @classmethod
    def from_dict(cls, d: CredentialRecordDict) -> 'Credential':
        return cls(site=d['site'], account=d['account'], enc_blob=d['enc'], version=d['v'], dup_tag=d.get('dup_tag'))

    def to_dict(self) -> CredentialRecordDict:
        d = asdict(self)
        d['enc'] = d.pop('enc_blob')
        d['v'] = d.pop('version')
        if self.dup_tag:
            d['dup_tag'] = self.dup_tag
        return d