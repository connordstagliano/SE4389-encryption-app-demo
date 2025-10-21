# `encryption.py` — Documentation

This module handles all cryptographic operations for the project.
It converts user passwords into strong keys, verifies master credentials, and encrypts or decrypts stored site passwords.
It’s self-contained, stateless, and does not interface with the filesystem.
Persistence (saving/loading) is handled by the backend.

## Core Concepts

### Key Derivation (KDF)

User passwords are never used directly for encryption.
Instead, **scrypt** expands them into a 32-byte **root key** using parameters (`N=16384`, `r=8`, `p=1`) and a random 16-byte **salt**.
This makes brute-force attacks extremely expensive.

The salt and KDF parameters are stored with the user’s master record so the same root key can be regenerated later.
Without the exact password and parameters, the key cannot be reproduced.

### HKDF Subkeys

From the root key, three distinct subkeys are derived using **HKDF**:

| Subkey     | Purpose                                                               | Info label    |
| ---------- | --------------------------------------------------------------------- | ------------- |
| `auth-key` | Builds a verifier HMAC for master password validation                 | `b"auth-key"` |
| `enc-key`  | Used for AES-GCM encryption and decryption of site passwords          | `b"enc-key"`  |
| `dup-key`  | Generates deterministic, irreversible tags to detect reused passwords | `b"dup-key"`  |

Each subkey serves a separate role and cannot be used to recover others.

### AES-GCM Encryption

Passwords are encrypted with **AES-256 in GCM mode**, which provides both confidentiality and integrity.
If any part of the ciphertext or metadata changes, decryption fails.

### AAD (Associated Authenticated Data)

Each password encryption binds the data to its metadata string `f"{site}|{account}"`.
Changing either field later causes decryption to fail, preventing ciphertext swapping or tampering.

### Nonce

Each encryption uses a random 96-bit (12-byte) **nonce** generated with `os.urandom()`.
Nonces are never reused for the same key, preserving AES-GCM’s security.

## Encryption Process

This section explains what happens at each stage of encryption and decryption.

### 1. Master password → Root key

When a user creates or logs in, their master password is fed into scrypt.
scrypt takes the password, salt, and parameters, and outputs a 32-byte root key.
This key is never stored and exists only in memory.
The salt and KDF configuration are saved with the master record for later use.

### 2. Root key → Subkeys

The root key passes through HKDF to generate three separate subkeys (`auth-key`, `enc-key`, `dup-key`).
Each key is derived deterministically but used for a single purpose only.

### 3. Encrypting a site password

The function `encrypt_password()` performs the following steps:

1. Derive the `enc-key` using HKDF.
2. Generate a random 12-byte nonce.
3. Build the AAD string: `f"{site}|{account}"`.
4. Encrypt the plaintext password using AES-GCM with:

   * Key: derived `enc-key`
   * Nonce: random value
   * AAD: metadata
   * Plaintext: password
5. Output a base64-encoded structure:

```json
{
  "nonce": "<urlsafe-b64>",
  "ciphertext": "<urlsafe-b64>"
}
```

No plaintext or key material is stored.

### 4. Decrypting a site password

`decrypt_password()` reverses the process:

1. Re-derive the same root and encryption keys.
2. Rebuild the same AAD (`site|account`).
3. Pass the nonce, ciphertext, and AAD into AES-GCM decryption.
4. Return the original password if authentication succeeds.
5. If anything mismatches — wrong password, wrong site, or tampered data — AES-GCM raises `InvalidTag`.

### 5. Verifier HMAC

The master record contains a **verifier HMAC** built with the `auth-key`.
During login, the provided password re-creates the same root key and verifier.
If the computed verifier matches the stored one (checked in constant time), the password is valid.
No decryption occurs during this step.

### 6. Duplicate Detection Tag

`make_duplicate_tag()` uses HMAC with the `dup-key` to generate a deterministic, irreversible identifier for a plaintext password.
Matching tags indicate reused passwords under the same root key, without exposing the plaintext itself.

### 7. Master Password Rotation

When a user changes their master password:

1. The old master password is verified.
2. The old root key decrypts all site passwords.
3. A new master record is created from the new password.
4. Each password is re-encrypted under the new root key.
5. All of this happens in memory — no file operations.

### 8. Integrity and Tamper Resistance

Both AES-GCM and HMAC provide integrity checks:

* Any modification to ciphertext, nonce, or metadata breaks decryption.
* Stored JSON blobs can be safely persisted without additional signatures.
* Passwords cannot be recovered without the correct master password and parameters.

## Functions

| Function                                                                      | Purpose                                                                                  |
| ----------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `make_master_record(username, password)`                                      | Builds a master record containing KDF parameters and a verifier HMAC. No secrets stored. |
| `verify_master(username, password, record)`                                   | Verifies the master password. Returns `(ok, root_key)` if valid.                         |
| `encrypt_password(plaintext, root_key, *, site, account)`                     | Encrypts a password using AES-GCM with metadata as AAD.                                  |
| `decrypt_password(enc_blob, root_key, *, site, account)`                      | Decrypts a stored password or raises `InvalidTag` on tampering or mismatch.              |
| `make_duplicate_tag(plaintext, root_key)`                                     | Generates a reuse-detection tag for plaintext passwords.                                 |
| `rotate_master_password(record, username, old_password, new_password, creds)` | Re-encrypts all stored credentials under a new master password.                          |
| `validate_master_record(record)`                                              | Checks structure and safety of the provided master record JSON.                          |

## Data Structures

These JSON formats represent the current design but are **not final**.
Future revisions will support multiple passwords per site using unique IDs rather than relying on the `site|account` pair.

### MasterRecord

```json
{
  "version": "taco-v1",
  "username": "alice",
  "kdf": { "name": "scrypt", "n": 16384, "r": 8, "p": 1, "length": 32, "salt": "<urlsafe-b64>" },
  "verifier": "<urlsafe-b64>"
}
```

### EncBlob

```json
{
  "nonce": "<urlsafe-b64>",
  "ciphertext": "<urlsafe-b64>"
}
```

### CredentialRecord

```json
{
  "site": "example.com",
  "account": "alice@example.com",
  "enc": { "nonce": "...", "ciphertext": "..." },
  "v": "taco-v1"
}
```

Planned future versions will replace `site` and `account` as identifiers with a unique `uid` per credential.

## Demo and Testing

A companion script, `encryption_demo.py`, showcases:

* Creating and verifying master records
* Encrypting and decrypting multiple site passwords
* Detecting reuse via duplicate tags
* Rotating master passwords

Run it locally with:

```bash
python encryption_demo.py
```

It runs fully in memory and does not write any data to disk.
