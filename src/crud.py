from fastapi import HTTPException
from sqlalchemy.orm import Session
from . import models, schemas
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()


def create_user(db: Session, user: schemas.UserCreate):
    hashed_password = pwd_context.hash(user.password)
    db_user = models.User(
        email=user.email, hashed_password=hashed_password, username=user.username
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def get_magazines(db: Session):
    return db.query(models.Magazine).all()


def get_user_subscriptions(db: Session, user_id: int):
    return (
        db.query(models.Subscription)
        .filter(
            models.Subscription.user_id == user_id,
            models.Subscription.is_active == True,
        )
        .all()
    )


def authenticate_user(db: Session, username: str, password: str):
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        return False
    if not pwd_context.verify(password, user.hashed_password):
        return False
    return user


def create_password_reset_token(email: str):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"exp": expire, "sub": email}
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_password_reset_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            return None
        return email
    except JWTError:
        return None


def reset_password(db: Session, email: str, new_password: str):
    user = get_user_by_email(db, email)
    if user:
        hashed_password = pwd_context.hash(new_password)
        user.hashed_password = hashed_password
        db.commit()
        db.refresh(user)
        return user
    return None


def get_user_by_token(db: Session, token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=401, detail="Invalid authentication credentials"
            )
    except jwt.JWTError:
        raise HTTPException(
            status_code=401, detail="Invalid authentication credentials"
        )

    user = db.query(models.User).filter(models.User.username == username).first()
    if user is None:
        raise HTTPException(
            status_code=401, detail="Invalid authentication credentials"
        )
    return user


def create_magazine(db: Session, magazine: schemas.Magazine):
    db_magazine = models.Magazine(**magazine.dict())
    db.add(db_magazine)
    db.commit()
    db.refresh(db_magazine)
    return db_magazine


def update_magazine(db: Session, magazine_id: int, magazine: schemas.Magazine):
    db_magazine = (
        db.query(models.Magazine).filter(models.Magazine.id == magazine_id).first()
    )
    if db_magazine is None:
        return None
    for key, value in magazine.dict().items():
        setattr(db_magazine, key, value)
    db.commit()
    db.refresh(db_magazine)
    return db_magazine


def get_subscription(db: Session, subscription_id: int):
    return (
        db.query(models.Subscription)
        .filter(
            models.Subscription.id == subscription_id,
            models.Subscription.is_active == True,
        )
        .first()
    )


def update_subscription(
    db: Session, subscription_id: int, subscription_update: schemas.SubscriptionBase
):
    subscription = (
        db.query(models.Subscription)
        .filter(models.Subscription.id == subscription_id)
        .first()
    )
    if subscription:
        # Deactivate the current subscription
        subscription.is_active = False
        db.commit()
        db.refresh(subscription)

        # Create a new subscription
        new_subscription = models.Subscription(
            user_id=subscription.user_id,
            plan_id=(
                subscription_update.plan_id
                if subscription_update.plan_id
                else subscription.plan_id
            ),
            price=subscription.price,  # Assuming price remains the same
            next_renewal_date=datetime.now()
            + timedelta(days=30),  # Assuming a 30-day plan for simplicity
            is_active=True,
            magazine_id=(
                subscription_update.magazine_id
                if subscription_update.magazine_id
                else subscription.magazine_id
            ),
        )
        db.add(new_subscription)
        db.commit()
        db.refresh(new_subscription)
        return new_subscription
    return None


def delete_subscription(db: Session, subscription_id: int):
    subscription = (
        db.query(models.Subscription)
        .filter(models.Subscription.id == subscription_id)
        .first()
    )
    if subscription:
        subscription.is_active = False
        db.commit()
        db.refresh(subscription)
    return subscription


def create_subscription(db: Session, subscription: schemas.SubscriptionBase):
    db_subscription = models.Subscription(
        user_id=subscription.user_id,
        magazine_id=subscription.magazine_id,
        plan_id=subscription.plan_id,
        price=subscription.price,
        next_renewal_date=subscription.next_renewal_date,
        is_active=True,
    )
    db.add(db_subscription)
    db.commit()
    db.refresh(db_subscription)
    return db_subscription


def create_plan(db: Session, plan: schemas.PlanBase):
    db_plan = models.Plan(
        title=plan.title,
        description=plan.description,
        renewal_period=plan.renewal_period,
    )
    db.add(db_plan)
    db.commit()
    db.refresh(db_plan)
    return db_plan


def get_plan(db: Session):
    return db.query(models.Plan).all()


def get_specific_plan(db: Session, plan_id: int):
    return db.query(models.Plan).filter(models.Plan.id == plan_id).first()


def update_plan(db: Session, plan_id: int, plan: schemas.PlanBase):
    db_plan = db.query(models.Plan).filter(models.Plan.id == plan_id).first()
    if db_plan is None:
        return None
    db_plan.title = plan.title
    db_plan.description = plan.description
    db_plan.renewal_period = plan.renewal_period
    db.commit()
    db.refresh(db_plan)
    return db_plan


def delete_plan(db: Session, plan_id: int):
    db_plan = db.query(models.Plan).filter(models.Plan.id == plan_id).first()
    if db_plan is None:
        return None
    db.delete(db_plan)
    db.commit()
    return db_plan
