from pydantic import BaseModel
from passlib.context import CryptContext
from typing import Optional


class User(BaseModel):
    user_id: str
    nickname: Optional[str] = None
    profile: Optional[str] = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, user_id: str):
    if user_id in db:
        user_dict = db[user_id]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, user_id: str, password: str):
    user = get_user(fake_db, user_id)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user