"""
encryption.py — TACO (Totally Amateur Credential Organizer) encryption helpers
"""

from __future__ import annotations

import base64
import hmac
import json
import os
from dataclasses import dataclass
from typing import Mapping, Optional, Tuple, TypedDict, cast

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

VERSION = "taco-v1"
HKDF_SALT = b"taco-v1-hkdf-salt"

# typed JSON shapes


class KDFParamsDict(TypedDict):
    name: str
    n: int
    r: int
    p: int
    length: int
    salt: str  # urlsafe b64


class MasterRecord(TypedDict):
    version: str
    username: str
    kdf: KDFParamsDict
    verifier: str  # urlsafe b64


class EncBlob(TypedDict):
    nonce: str
    ciphertext: str


class CredentialRecord(TypedDict):
    site: str
    account: str
    enc: EncBlob
    v: str


# helpers


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def _b64d(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def generate_salt(nbytes: int = 16) -> bytes:
    if nbytes < 16:
        raise ValueError("salt must be at least 16 bytes")
    return os.urandom(nbytes)


def _coerce_int(value: object, name: str, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            raise TypeError(
                f"{name} must be an integer or numeric string (got {value!r})"
            )
    try:
        return int(value)  # type: ignore[arg-type]
    except Exception:
        raise TypeError(
            f"{name} must be an integer-like value (got {type(value).__name__})"
        )


# KDF params


@dataclass(frozen=True)
class KDFParams:
    name: str = "scrypt"
    n: int = 1 << 14  # 16384
    r: int = 8
    p: int = 1
    length: int = 32
    salt: str = ""  # urlsafe b64

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

    def to_dict(self) -> KDFParamsDict:
        return {
            "name": self.name,
            "n": self.n,
            "r": self.r,
            "p": self.p,
            "length": self.length,
            "salt": self.salt,
        }

    @staticmethod
    def from_dict(d: Mapping[str, object]) -> "KDFParams":
        name = str(d.get("name", "scrypt"))
        n = _coerce_int(d.get("n"), "kdf.n", 1 << 14)
        r = _coerce_int(d.get("r"), "kdf.r", 8)
        p = _coerce_int(d.get("p"), "kdf.p", 1)
        length = _coerce_int(d.get("length"), "kdf.length", 32)
        salt_obj = d.get("salt")
        if not isinstance(salt_obj, str):
            raise TypeError("kdf.salt must be a url-safe base64 string")
        return KDFParams(name=name, n=n, r=r, p=p, length=length, salt=salt_obj)


def derive_root_key(password: str, kdf: KDFParams) -> bytes:
    if kdf.name.lower() != "scrypt":
        raise ValueError("unsupported KDF")
    if kdf.n < (1 << 14) or kdf.r < 8 or kdf.p < 1 or kdf.length < 32:
        raise ValueError("KDF params too weak")
    kdf_fn = Scrypt(salt=_b64d(kdf.salt), length=kdf.length, n=kdf.n, r=kdf.r, p=kdf.p)
    return kdf_fn.derive(password.encode("utf-8"))


def derive_subkey(root_key: bytes, info: bytes, length: int = 32) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=HKDF_SALT, info=info)
    return hkdf.derive(root_key)


def _hmac_sha256(key: bytes, msg: bytes) -> bytes:
    h = crypto_hmac.HMAC(key, hashes.SHA256())
    h.update(msg)
    return h.finalize()


# master record


def make_master_record(
    username: str, password: str, kdf: Optional[KDFParams] = None
) -> MasterRecord:
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
    username: str, password: str, record: Mapping[str, object]
) -> Tuple[bool, Optional[bytes]]:
    try:
        version = record.get("version")
        if version != VERSION:
            return False, None

        uname = record.get("username")
        if not isinstance(uname, str) or uname != username:
            return False, None

        kdf_raw = record.get("kdf")
        if not isinstance(kdf_raw, dict):
            return False, None
        kdf_map: Mapping[str, object] = cast(Mapping[str, object], kdf_raw)
        kdf = KDFParams.from_dict(kdf_map)

        root_key = derive_root_key(password, kdf)
        auth_key = derive_subkey(root_key, b"auth-key")

        verifier_b64 = record["verifier"]  # type: ignore[index]
        expected = _b64d(verifier_b64)  # type: ignore[arg-type]
        actual = _hmac_sha256(auth_key, f"verify|{username}|{VERSION}".encode("utf-8"))

        if hmac.compare_digest(expected, actual):
            return True, root_key
        return False, None
    except Exception:
        return False, None


# encryption


def enc_key_from_root(root_key: bytes) -> bytes:
    return derive_subkey(root_key, b"enc-key")


def encrypt_password(
    plaintext_password: str, root_key: bytes, *, site: str, account: str
) -> EncBlob:
    if not plaintext_password:
        raise ValueError("plaintext_password must be a non-empty string")
    if not site or not account:
        raise ValueError("site and account are required for AAD binding")

    key = enc_key_from_root(root_key)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce
    aad = f"{site}|{account}".encode("utf-8")
    ct = aesgcm.encrypt(nonce, plaintext_password.encode("utf-8"), aad)
    return {"nonce": _b64e(nonce), "ciphertext": _b64e(ct)}


def decrypt_password(
    enc: EncBlob,
    root_key: bytes,
    *,
    site: str,
    account: str,
) -> str:
    nonce_b64 = enc["nonce"]
    ct_b64 = enc["ciphertext"]

    key = enc_key_from_root(root_key)
    aesgcm = AESGCM(key)
    nonce = _b64d(nonce_b64)
    ct = _b64d(ct_b64)
    aad = f"{site}|{account}".encode("utf-8")
    try:
        pt = aesgcm.decrypt(nonce, ct, aad)
        return pt.decode("utf-8")
    except InvalidTag as e:
        raise InvalidTag(
            "decryption failed (wrong credentials or tampered data)"
        ) from e


# minimal record helpers


def make_credential_record(
    site: str, account: str, enc_blob: EncBlob
) -> CredentialRecord:
    return {"site": site, "account": account, "enc": enc_blob, "v": VERSION}


def validate_master_record(record: Mapping[str, object]) -> None:
    version = record.get("version")
    if version != VERSION:
        raise ValueError("unsupported version")

    try:
        username = cast(str, record["username"])  # type: ignore[index]
        verifier = cast(str, record["verifier"])  # type: ignore[index]
    except Exception:
        raise ValueError("username/verifier missing/invalid")

    if not username:
        raise ValueError("username missing/invalid")
    if not verifier:
        raise ValueError("verifier missing/invalid")

    kdf_raw = record.get("kdf")
    if not isinstance(kdf_raw, dict):
        raise ValueError("kdf missing/invalid")
    kdf_map: Mapping[str, object] = cast(Mapping[str, object], kdf_raw)
    kdf = KDFParams.from_dict(kdf_map)

    if kdf.n < (1 << 14) or kdf.r < 8 or kdf.p < 1 or kdf.length < 32:
        raise ValueError("KDF params too weak")
    _ = _b64d(kdf.salt)  # decode check


# demo

if __name__ == "__main__":
    print("taco demo: creating master record, encrypting and decrypting one password\n")

    username = "demo_user"
    password = "correct horse battery staple"
    site = "example.com"
    account = "demo@example.com"
    secret_pw = "P@ssw0rd!"

    master = make_master_record(username, password)
    print("master record JSON:")
    print(json.dumps(master, indent=2))
    print()

    ok, root = verify_master(username, password, master)
    print(f"verify_master -> {ok}")
    assert ok and root is not None

    enc = encrypt_password(secret_pw, root, site=site, account=account)
    cred = make_credential_record(site, account, enc)
    print("credential record JSON:")
    print(json.dumps(cred, indent=2))
    print()

    decrypted = decrypt_password(enc, root, site=site, account=account)
    print("decrypted password:", decrypted)
    assert decrypted == secret_pw

    print("\nOK.")
