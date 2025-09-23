"""
encryption.py — TACO (Totally Amateur Credential Organizer) encryption helpers
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import Dict, Optional

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def _b64d(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def generate_salt(nbytes: int = 16) -> bytes:
    if nbytes < 16:
        raise ValueError("salt must be at least 16 bytes")
    return os.urandom(nbytes)


@dataclass(frozen=True)
class KDFParams:
    name: str = "scrypt"
    n: int = 1 << 14  # 16384
    r: int = 8
    p: int = 1
    length: int = 32
    salt: str = ""  # b64

    @staticmethod
    def create(
        n: int = 1 << 14,
        r: int = 8,
        p: int = 1,
        length: int = 32,
        salt: Optional[bytes] = None,
    ) -> "KDFParams":
        if salt is None:
            salt = generate_salt(16)
        return KDFParams(n=n, r=r, p=p, length=length, salt=_b64e(salt))

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "n": self.n,
            "r": self.r,
            "p": self.p,
            "length": self.length,
            "salt": self.salt,
        }

    @staticmethod
    def from_dict(d: Dict[str, object]) -> "KDFParams":
        return KDFParams(
            name=str(d.get("name", "scrypt")),
            n=int(d.get("n", 1 << 14)),
            r=int(d.get("r, ", 8)) if "r, " in d else int(d.get("r", 8)),
            p=int(d.get("p", 1)),
            length=int(d.get("length", 32)),
            salt=str(d["salt"]),
        )


def derive_root_key(password: str, kdf: KDFParams) -> bytes:
    if kdf.name.lower() != "scrypt":
        raise ValueError("unsupported KDF")
    if kdf.n < (1 << 14) or kdf.r < 8 or kdf.p < 1 or kdf.length < 32:
        raise ValueError("KDF params too weak")
    kdf_fn = Scrypt(
        salt=_b64d(kdf.salt),
        length=kdf.length,
        n=kdf.n,
        r=kdf.r,
        p=kdf.p,
    )
    return kdf_fn.derive(password.encode("utf-8"))
