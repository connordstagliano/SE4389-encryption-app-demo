from storage.abstract_storage import AbstractStorage
from entities.user_entity import User
from encryption import (
    verify_master,
    make_master_record,
    validate_master_record,
    rotate_master_password,
    decrypt_password,
    make_duplicate_tag,
)
from entities.credential_entity import Credential

def create_user(storage: AbstractStorage, username: str, password: str) -> User:
    if storage.get_user(username) is not None:
        raise ValueError("User already exists")
    
    master_record = make_master_record(username, password)
    validate_master_record(master_record)

    user = User(username, master_record)
    storage.save_user(user)
    
    return user

def verify_user_and_get_root(storage: AbstractStorage, username: str, password: str) -> bytes:
    user = storage.get_user(username)
    if user is None:
        raise ValueError("Invalid credentials")

    ok, root = verify_master(username, password, user.master_record)
    if not ok or root is None:
        raise ValueError("Invalid credentials")
    return root

def rotate_user_password(
    storage: AbstractStorage,
    username: str,
    current_password: str,
    new_password: str,
) -> None:
    user = storage.get_user(username)
    if not user:
        raise ValueError("Invalid credentials")

    cred_dicts = [c.to_dict() for c in user.credentials]
    new_master_record, new_creds = rotate_master_password(
        user.master_record, username, current_password, new_password, cred_dicts
    )

    ok, new_root_key = verify_master(username, new_password, new_master_record)
    if not ok or new_root_key is None:
        raise ValueError("Rotation failed")

    new_credentials = []
    for new_cred_dict in new_creds:
        new_cred = Credential.from_dict(new_cred_dict)

        pw = decrypt_password(
            new_cred.enc_blob,
            new_root_key,
            site=new_cred.site,
            account=new_cred.account,
        )
        new_cred.dup_tag = make_duplicate_tag(pw, new_root_key)
        new_credentials.append(new_cred)

    user.master_record = new_master_record
    user.credentials = new_credentials

    storage.save_user(user)