# encryption_demo.py — multi-credential showcase using encryption.py

from __future__ import annotations

import json
from typing import Mapping, cast

from encryption import (
    EncBlob,
    CredentialRecord,
    InvalidTag,
    make_master_record,
    verify_master,
    encrypt_password,
    decrypt_password,
    make_credential_record,
    make_duplicate_tag,
    rotate_master_password,
    validate_master_record,
    # internal helpers: fine for a demo
    _b64d,  # pyright: ignore[reportPrivateUsage]
    _b64e,  # pyright: ignore[reportPrivateUsage]
)


def require_root(ok: bool, root: bytes | None) -> bytes:
    """Narrow (ok, root) to a definite bytes key or exit."""
    if not ok or root is None:
        raise SystemExit("login/verification failed")
    return root


def main() -> None:
    print("taco demo: multi-credential showcase\n")

    # create master record for demo_user
    username = "demo_user"
    password = "correct horse battery staple"
    master = make_master_record(username, password)
    print("master record (stored JSON):")
    print(json.dumps(master, indent=2))
    print()

    # login
    ok, root_opt = verify_master(username, password, master)
    print("login ok:", ok)
    root = require_root(ok, root_opt)
    print()

    # create multiple credentials (two reuse the same plaintext)
    inputs: list[tuple[str, str, str]] = [
        ("example.com", "alice@example.com", "S3cr3t!"),
        ("work.example.com", "alice@work", "L0ngAnd$afe"),
        ("photos.example", "alice@photos", "S3cr3t!"),  # reused
        ("bank.example", "alice@bank", "V3ry$tr0ngP@ss"),
    ]

    creds: list[CredentialRecord] = []
    for site, account, pw in inputs:
        enc = encrypt_password(pw, root, site=site, account=account)
        cred = make_credential_record(site, account, enc)
        creds.append(cred)

    print("created credentials (nonce + ciphertext shown):")
    for i, c in enumerate(creds, 1):
        print(
            f" {i}. {c['site']} / {c['account']} -> enc keys: {list(c['enc'].keys())}"
        )
    print()

    # duplicate detection (backend-style, without persisting plaintext)
    dup_index: dict[str, list[tuple[str, str]]] = {}
    for c in creds:
        site: str = c["site"]
        account: str = c["account"]
        pw = decrypt_password(c["enc"], root, site=site, account=account)
        tag = make_duplicate_tag(pw, root)
        dup_index.setdefault(tag, []).append((site, account))

    print("duplicate detection results (groups of identical plaintexts):")
    any_dupes = False
    for tag, items in dup_index.items():
        if len(items) > 1:
            any_dupes = True
            print(" - reused password for:")
            for site, account in items:
                print(f"    * {site} / {account}")
    if not any_dupes:
        print(" - none")
    print()

    # tamper demo: wrong AAD (site mismatch) -> fail
    print("tamper demo: attempt decrypt with wrong site (expected failure):")
    bad = creds[0]
    try:
        decrypt_password(bad["enc"], root, site="evil.com", account=bad["account"])
        print("  unexpected: decrypt succeeded with wrong site")
    except InvalidTag:
        print("  expected: InvalidTag (AAD mismatch)")
    print()

    # corruption demo: flip a bit in ciphertext -> fail
    print(
        "corruption demo: attempt decrypt with corrupted ciphertext (expected failure):"
    )
    victim = creds[1]
    enc_blob: EncBlob = victim["enc"]
    ct_str: str = enc_blob["ciphertext"]
    raw_ct = _b64d(ct_str)
    flipped = bytearray(raw_ct)
    flipped[0] ^= 0x01
    corrupt_enc: EncBlob = {
        "nonce": enc_blob["nonce"],
        "ciphertext": _b64e(bytes(flipped)),
    }
    try:
        decrypt_password(
            corrupt_enc, root, site=victim["site"], account=victim["account"]
        )
        print("  unexpected: decrypt succeeded with corrupted ciphertext")
    except InvalidTag:
        print("  expected: InvalidTag (integrity failure)")
    print()

    # validate master record JSON round-trip (simulates DB load)
    print("validate master record JSON round-trip:")
    master_json = json.dumps(master)
    loaded = json.loads(master_json)
    try:
        validate_master_record(cast(Mapping[str, object], loaded))
        print("  validate_master_record: OK")
    except Exception as e:
        print("  validate_master_record: FAILED:", type(e).__name__, str(e))
    print()

    # login failure demo
    print("login failure demo:")
    bad_ok, _ = verify_master(username, "incorrect password", master)
    print("  expected False:", bad_ok)
    print()

    # rotation: re-encrypt all credentials under a new master password
    print("rotate master password demo: re-encrypt all credentials under new master")
    new_master, reencrypted = rotate_master_password(
        master, username, password, "evenNewerMaster!", creds
    )
    print(
        "  new master created; first cred re-encrypted -> enc keys:",
        list(reencrypted[0]["enc"].keys()),
    )
    new_ok, new_root_opt = verify_master(username, "evenNewerMaster!", new_master)
    print("  verify new master:", new_ok)
    new_root = require_root(new_ok, new_root_opt)

    # duplicate groups after rotation (should mirror earlier grouping)
    new_dup_index: dict[str, list[tuple[str, str]]] = {}
    for c in reencrypted:
        site: str = c["site"]
        account: str = c["account"]
        pw = decrypt_password(c["enc"], new_root, site=site, account=account)
        tag = make_duplicate_tag(pw, new_root)
        new_dup_index.setdefault(tag, []).append((site, account))
    print("  duplicate groups after rotation:")
    any_dupes2 = False
    for tag, items in new_dup_index.items():
        if len(items) > 1:
            any_dupes2 = True
            print("   - reused password for:")
            for site, account in items:
                print(f"      * {site} / {account}")
    if not any_dupes2:
        print("   - none")
    print()

    # final decrypt check for each credential after rotation
    print("final decrypt test for all re-encrypted credentials:")
    for c in reencrypted:
        site: str = c["site"]
        account: str = c["account"]
        pw = decrypt_password(c["enc"], new_root, site=site, account=account)
        print(f"  {site} / {account} -> {pw}")
    print()

    print("demo complete — everything behaved as expected.")


if __name__ == "__main__":
    main()
