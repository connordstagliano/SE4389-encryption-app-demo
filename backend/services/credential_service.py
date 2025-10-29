from storage.abstract_storage import AbstractStorage
from entities.credential_entity import Credential
from typing import List

from encryption import encrypt_password, make_credential_record, make_duplicate_tag, decrypt_password, InvalidTag

def add_credential(storage: AbstractStorage, username: str, root_key: bytes, site: str, account: str, site_password: str) -> Credential:
    user = storage.get_user(username)
    if not user:
        raise ValueError("User not found")
    
    enc_blob = encrypt_password(site_password, root_key, site=site, account=account)
    cred_dict = make_credential_record(site, account, enc_blob)

    cred = Credential.from_dict(cred_dict)

    cred.dup_tag = make_duplicate_tag(site_password, root_key)
    user.credentials.append(cred)

    storage.save_user(user)

    return cred

def check_credential_dup(storage, username, root_key, site_password):
    user = storage.get_user(username)
    warning = False
    count = 0

    dupCheck = make_duplicate_tag(site_password, root_key)
    for credential in user.credentials:
            count += 1
    if count >= 3:
        warning = True
        return "Warning, this password is reused 3 times", warning
    else:
        return "None", warning

    return check_credential_dup

def get_credentials(storage: AbstractStorage, username: str, root_key: bytes) -> List[Credential]:
    user = storage.get_user(username)
    if not user:
        raise ValueError("User not found")

    creds = []
    for cred in user.credentials:
        try:
            creds.append({
                **cred.to_dict(),
                'site_password': decrypt_password(cred.enc_blob, root_key, site=cred.site, account=cred.account)
            })
        except InvalidTag:
            raise ValueError("Decryption failed")

    return creds