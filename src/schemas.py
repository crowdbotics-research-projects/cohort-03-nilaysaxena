from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime


class UserBase(BaseModel):
    email: str


class UserCreate(UserBase):
    password: str
    username: str


class User(UserBase):
    id: int
    is_active: bool

    class Config:
        orm_mode = True


class MagazineBase(BaseModel):
    name: str
    description: str
    base_price: float
    discount: float


class Magazine(MagazineBase):
    id: int

    class Config:
        orm_mode = True


class PlanBase(BaseModel):
    title: str
    description: str
    renewal_period: int


class Plan(PlanBase):
    id: int

    class Config:
        orm_mode = True


class SubscriptionBase(BaseModel):
    user_id: int
    magazine_id: int
    plan_id: int
    price: float
    next_renewal_date: datetime


class Subscription(SubscriptionBase):
    id: int
    is_active: bool

    class Config:
        orm_mode = True


class Token(BaseModel):
    access_token: str
    token_type: str


class PasswordResetRequest(BaseModel):
    email: str


class PasswordReset(BaseModel):
    token: str
    new_password: str


class LoginRequest(BaseModel):
    username: str
    password: str
