"""
encryption.py — TACO (Totally Amateur Credential Organizer) encryption helpers
"""

from __future__ import annotations

import base64
import hmac
import json
import os
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

VERSION = "taco-v1"
HKDF_SALT = b"taco-v1-hkdf-salt"


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


def derive_subkey(root_key: bytes, info: bytes, length: int = 32) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=HKDF_SALT, info=info)
    return hkdf.derive(root_key)


def _hmac_sha256(key: bytes, msg: bytes) -> bytes:
    h = crypto_hmac.HMAC(key, hashes.SHA256())
    h.update(msg)
    return h.finalize()


def make_master_record(
    username: str, password: str, kdf: Optional[KDFParams] = None
) -> Dict[str, object]:
    if not username:
        raise ValueError("username required")
    kdf = kdf or KDFParams.create()
    root_key = derive_root_key(password, kdf)
    auth_key = derive_subkey(root_key, b"auth-key")
    verifier = _hmac_sha256(auth_key, f"verify|{username}|{VERSION}".encode("utf-8"))
    return {
        "version": VERSION,
        "username": username,
        "kdf": kdf.to_dict(),
        "verifier": _b64e(verifier),
    }


def verify_master(
    username: str, password: str, record: Dict[str, object]
) -> Tuple[bool, Optional[bytes]]:
    try:
        if record.get("version") != VERSION or record.get("username") != username:
            return False, None
        kdf = KDFParams.from_dict(record["kdf"])  # type: ignore[arg-type]
        root_key = derive_root_key(password, kdf)
        auth_key = derive_subkey(root_key, b"auth-key")
        expected = _b64d(str(record["verifier"]))  # type: ignore[index]
        actual = _hmac_sha256(auth_key, f"verify|{username}|{VERSION}".encode("utf-8"))
        if hmac.compare_digest(expected, actual):
            return True, root_key
        return False, None
    except Exception:
        return False, None
