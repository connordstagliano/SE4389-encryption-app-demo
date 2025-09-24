from abc import ABC, abstractmethod
from typing import Optional, List

from entities.user_entity import User
from entities.credential_entity import Credential

class AbstractStorage(ABC):
    @abstractmethod
    def save_user(self, user: User) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_user(self, username: str) -> Optional[User]:
        raise NotImplementedError
    
    @abstractmethod
    def save_credential(self, username: str, credential: Credential) -> None:
        raise NotImplementedError
    
    @abstractmethod
    def get_credentials(self, username: str) -> List[Credential]:
        raise NotImplementedError