from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, Float, DateTime
from sqlalchemy.orm import relationship
from .database import Base


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    username = Column(String, unique=True, index=True)  # Added username field
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)


class Magazine(Base):
    __tablename__ = "magazines"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    description = Column(String)
    base_price = Column(Float)
    discount_quarterly = Column(Float)
    discount_half_yearly = Column(Float)
    discount_annual = Column(Float)


class Plan(Base):
    __tablename__ = "plans"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(String)
    renewal_period = Column(Integer)


class Subscription(Base):
    __tablename__ = "subscriptions"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    magazine_id = Column(Integer, ForeignKey("magazines.id"))
    plan_id = Column(Integer, ForeignKey("plans.id"))
    price = Column(Float)
    next_renewal_date = Column(DateTime)
    is_active = Column(Boolean, default=True)

    user = relationship("User")
    magazine = relationship("Magazine")
    plan = relationship("Plan")
