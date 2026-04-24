from pydantic import BaseModel
from typing import Optional


class UserRegister(BaseModel):
    username: str
    email: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class CommentCreate(BaseModel):
    comment: str
    safe_mode: bool = False


class CSRFProfileUpdate(BaseModel):
    email: str
    bio: str


class AttackLog(BaseModel):
    ip_address: str
    attack_type: str
    payload: str
    status: str
    endpoint: str
