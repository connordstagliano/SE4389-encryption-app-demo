"""
encryption.py — TACO (Totally Amateur Credential Organizer) encryption helpers

Quickstart (minimal flow)
-------------------------
    from encryption import (
        make_master_record, verify_master,
        encrypt_password, decrypt_password,
        make_credential_record
    )

    # 1) create/store master record once (e.g., at signup)
    master = make_master_record("alice", "correct horse battery staple")

    # 2) login (derive root key if password is correct)
    ok, root = verify_master("alice", "correct horse battery staple", master)
    assert ok and root is not None

    # 3) encrypt one site password for storage
    enc = encrypt_password("S3cr3t!", root, site="example.com", account="alice@example.com")
    cred = make_credential_record("example.com", "alice@example.com", enc)

    # 4) decrypt on demand (must pass the same site/account values used for encrypt)
    pw = decrypt_password(cred["enc"], root, site="example.com", account="alice@example.com")

Design notes
------------
- Master password -> scrypt root key -> HKDF subkeys (auth, enc, dup)
- Master record stores only KDF params + HMAC verifier (no secret key material)
- AES-256-GCM for credential encryption; binds (site|account) as AAD to detect metadata tampering
- Everything is JSON-friendly and typed with TypedDicts for static checking
- Rotation helper is in-memory only (backend chooses persistence)
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

__all__ = [
    "VERSION",
    "KDFParams",
    "KDFParamsDict",
    "MasterRecord",
    "EncBlob",
    "CredentialRecord",
    "make_master_record",
    "verify_master",
    "encrypt_password",
    "decrypt_password",
    "make_credential_record",
    "validate_master_record",
    "rotate_master_password",
    "make_duplicate_tag",
]

VERSION = "taco-v1"
HKDF_SALT = b"taco-v1-hkdf-salt"

# typed JSON shapes


class KDFParamsDict(TypedDict):
    """Serialized KDF parameters kept inside the master record."""

    name: str
    n: int
    r: int
    p: int
    length: int
    salt: str  # urlsafe b64


class MasterRecord(TypedDict):
    """Whole master record you store server-side."""

    version: str
    username: str
    kdf: KDFParamsDict
    verifier: str  # urlsafe b64


class EncBlob(TypedDict):
    """Encrypted payload for a single site password."""

    nonce: str
    ciphertext: str


class CredentialRecord(TypedDict):
    """One credential entry (you can extend this in your backend schema)."""

    site: str
    account: str
    enc: EncBlob
    v: str
    # Optional field (add in your backend if you want duplicate detection):
    # dup_tag: str


# helpers


def _b64e(b: bytes) -> str:
    """urlsafe base64 encoder that omits '=' padding."""
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def _b64d(s: str) -> bytes:
    """urlsafe base64 decoder that tolerates missing '=' padding."""
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def generate_salt(nbytes: int = 16) -> bytes:
    """Cryptographically secure random salt."""
    if nbytes < 16:
        raise ValueError("salt must be at least 16 bytes")
    return os.urandom(nbytes)


def _coerce_int(value: object, name: str, default: int) -> int:
    """Narrow a JSON-loaded value to an int with friendly errors (for strict type checkers)."""
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
    """
    Parameters for scrypt derivation of the master root key.

    Defaults are intentionally conservative for this project:
    - n=16384, r=8, p=1, length=32
    """

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
        """Create params with a new random salt (urlsafe b64)."""
        if salt is None:
            salt = generate_salt(16)
        return KDFParams(n=n, r=r, p=p, length=length, salt=_b64e(salt))

    def to_dict(self) -> KDFParamsDict:
        """Serialize params for storage inside a master record."""
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
        """
        Reconstruct params from (possibly untyped) JSON.
        Raises TypeError/ValueError on shape issues.
        """
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
    """
    Derive a root key from the master password using scrypt.
    Returns 32 bytes.
    """
    if kdf.name.lower() != "scrypt":
        raise ValueError("unsupported KDF")
    if kdf.n < (1 << 14) or kdf.r < 8 or kdf.p < 1 or kdf.length < 32:
        raise ValueError("KDF params too weak")
    kdf_fn = Scrypt(salt=_b64d(kdf.salt), length=kdf.length, n=kdf.n, r=kdf.r, p=kdf.p)
    return kdf_fn.derive(password.encode("utf-8"))


def derive_subkey(root_key: bytes, info: bytes, length: int = 32) -> bytes:
    """
    HKDF-SHA256 subkey derivation with fixed salt for domain separation.
    `info` differentiates uses: b"auth-key", b"enc-key", b"dup-key".
    """
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=HKDF_SALT, info=info)
    return hkdf.derive(root_key)


def _hmac_sha256(key: bytes, msg: bytes) -> bytes:
    """One-shot HMAC-SHA256; returns raw bytes."""
    h = crypto_hmac.HMAC(key, hashes.SHA256())
    h.update(msg)
    return h.finalize()


# master record


def make_master_record(
    username: str, password: str, kdf: Optional[KDFParams] = None
) -> MasterRecord:
    """
    Create the JSON-storable master record.

    Stores:
      - version, username
      - KDF parameters (including salt)
      - verifier = HMAC(auth_key, "verify|username|version")

    Returns:
      MasterRecord
    """
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
    """
    Check username/password against a stored master record.

    Returns:
      (ok, root_key_if_ok_else_None)
    """
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

        # `verifier` is str if created by us; index + cast for Pylance
        verifier_b64 = record["verifier"]  # type: ignore[index]
        expected = _b64d(verifier_b64)  # type: ignore[arg-type]
        actual = _hmac_sha256(auth_key, f"verify|{username}|{VERSION}".encode("utf-8"))

        if hmac.compare_digest(expected, actual):
            return True, root_key
        return False, None
    except Exception:
        # Don’t leak why verification failed
        return False, None


# encryption


def enc_key_from_root(root_key: bytes) -> bytes:
    """Derive the AES-GCM key from the root key (HKDF info=b'enc-key')."""
    return derive_subkey(root_key, b"enc-key")


def encrypt_password(
    plaintext_password: str, root_key: bytes, *, site: str, account: str
) -> EncBlob:
    """
    Encrypt a single site password under AES-256-GCM.
    AAD (associated data) is f"{site}|{account}" — changing metadata breaks decryption.

    Returns:
      EncBlob { nonce, ciphertext } (urlsafe base64 strings)
    """
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
    """
    Decrypt an EncBlob produced by encrypt_password.
    Raises InvalidTag on wrong key/nonce/AAD/ciphertext.
    """
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


# optional duplicate detector


def make_duplicate_tag(plaintext_password: str, root_key: bytes) -> str:
    """
    Produce a stable tag to detect reused passwords WITHOUT revealing them.

    How to use:
      - On save, compute tag = make_duplicate_tag(plaintext, root_key)
      - Store tag as a string field (e.g., 'dup_tag') alongside the credential
      - To check duplicates, compare tags for equality

    Returns:
      urlsafe base64 string
    """
    dup_key = derive_subkey(root_key, b"dup-key")
    tag = _hmac_sha256(dup_key, plaintext_password.encode("utf-8"))
    return _b64e(tag)


# rotation


def rotate_master_password(
    record: Mapping[str, object],
    username: str,
    old_password: str,
    new_password: str,
    creds: list[CredentialRecord],
) -> Tuple[MasterRecord, list[CredentialRecord]]:
    """
    Re-encrypt all credentials under a NEW master password. Purely in-memory.

    Inputs:
      record  - existing MasterRecord (as loaded JSON)
      username, old_password - credentials to verify
      new_password - replacement master password
      creds   - list of CredentialRecord

    Returns:
      (new_master_record, new_credentials_list)

    Notes:
      - If you store a duplicate tag, recompute it under the new root key.
      - If decryption of any credential fails (tampered or wrong AAD), this will raise.
    """
    ok, old_root = verify_master(username, old_password, record)
    if not ok or old_root is None:
        raise ValueError("old master credentials invalid")

    new_master = make_master_record(username, new_password)
    ok2, new_root = verify_master(username, new_password, new_master)
    assert ok2 and new_root is not None  # should always succeed

    updated: list[CredentialRecord] = []
    for c in creds:
        site = c["site"]
        account = c["account"]
        pw = decrypt_password(c["enc"], old_root, site=site, account=account)
        new_enc = encrypt_password(pw, new_root, site=site, account=account)
        new_c: CredentialRecord = {
            "site": site,
            "account": account,
            "enc": new_enc,
            "v": VERSION,
        }
        # If you were storing a dup_tag, recompute it here:
        # new_c["dup_tag"] = make_duplicate_tag(pw, new_root)
        updated.append(new_c)

    return new_master, updated


# minimal record helpers


def make_credential_record(
    site: str, account: str, enc_blob: EncBlob
) -> CredentialRecord:
    """Wrap an EncBlob with minimal metadata. Extend in your backend as needed."""
    return {"site": site, "account": account, "enc": enc_blob, "v": VERSION}


def validate_master_record(record: Mapping[str, object]) -> None:
    """
    Validate the shape/strength of a master record (untrusted input).
    Raises ValueError on problems.
    """
    version = record.get("version")
    if version != VERSION:
        raise ValueError("unsupported version")

    # cast + presence checks to satisfy strict typing and keep runtime safety
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

    # optional duplicate tag (not stored by default)
    tag = make_duplicate_tag(secret_pw, root)
    print("duplicate tag (demo):", tag)
    print()

    # rotation demo (re-encrypt the single credential under a new master)
    new_master, new_creds = rotate_master_password(
        master, username, password, "new master pw", [cred]
    )
    print("rotated master JSON (truncated kdf.salt):")
    truncated_master: dict[str, object] = {**new_master}
    kdf_src = cast(Mapping[str, object], new_master["kdf"])  # TypedDict -> Mapping
    kdf_copy: dict[str, object] = {**kdf_src}
    salt_str = cast(str, kdf_copy["salt"])
    kdf_copy["salt"] = f"{salt_str[:8]}..."
    truncated_master["kdf"] = kdf_copy

    print(json.dumps(truncated_master, indent=2))
    print("rotated credentials count:", len(new_creds))
    print()

    decrypted = decrypt_password(
        new_creds[0]["enc"],
        verify_master(username, "new master pw", new_master)[1],  # type: ignore[index]
        site=site,
        account=account,
    )
    print("decrypted after rotation:", decrypted)
    assert decrypted == secret_pw

    print("\nOK.")
