from datetime import datetime, timedelta
from typing import List
from jose import JWTError, jwt
from fastapi import FastAPI, Depends, HTTPException, Query, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from src.auth import get_current_user
from . import models, schemas, crud, database
from passlib.context import CryptContext

models.Base.metadata.create_all(bind=database.engine)


# Secret key to encode and decode JWT tokens
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


# Dependency
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


@app.post("/users/login", response_model=schemas.Token)
async def login_for_access_token(
    login_request: schemas.LoginRequest, db: Session = Depends(get_db)
):
    user = crud.authenticate_user(db, login_request.username, login_request.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/users/register", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return crud.create_user(db=db, user=user)


@app.get("/magazines/", response_model=List[schemas.Magazine])
def read_magazines(
    skip: int = 0,
    limit: int = 10,
    db: Session = Depends(get_db),
    token: str = Depends(oauth2_scheme),
):
    current_user = get_current_user(db, token)
    magazines = crud.get_magazines(db)
    return magazines


@app.post("/magazines/", response_model=schemas.Magazine)
def create_magazine(
    magazine: schemas.MagazineBase,
    db: Session = Depends(get_db),
    token: str = Depends(oauth2_scheme),
):
    current_user = get_current_user(db, token)
    return crud.create_magazine(db=db, magazine=magazine)


@app.put("/magazines/{magazine_id}", response_model=schemas.Magazine)
def update_magazine(
    magazine_id: int,
    magazine: schemas.MagazineBase,
    db: Session = Depends(get_db),
    token: str = Depends(oauth2_scheme),
):
    current_user = get_current_user(db, token)
    db_magazine = crud.get_magazine(db, magazine_id=magazine_id)
    if not db_magazine:
        raise HTTPException(status_code=404, detail="Magazine not found")
    return crud.update_magazine(db=db, magazine_id=magazine_id, magazine=magazine)


@app.get("/subscriptions/{subscription_id}", response_model=schemas.Subscription)
async def get_subscription(subscription_id: int, db: Session = Depends(get_db)):
    subscription = crud.get_subscription(db, subscription_id)
    if subscription is None:
        raise HTTPException(
            status_code=404, detail="Subscription not found or inactive"
        )
    return subscription


@app.put("/subscriptions/{subscription_id}", response_model=schemas.Subscription)
async def update_subscription(
    subscription_id: int,
    subscription_update: schemas.SubscriptionBase,
    db: Session = Depends(get_db),
):
    subscription = crud.update_subscription(db, subscription_id, subscription_update)
    if subscription is None:
        raise HTTPException(status_code=404, detail="Subscription not found")
    return subscription


@app.delete("/subscriptions/{subscription_id}", response_model=schemas.Subscription)
async def delete_subscription(subscription_id: int, db: Session = Depends(get_db)):
    subscription = crud.delete_subscription(db, subscription_id)
    if subscription is None:
        raise HTTPException(status_code=404, detail="Subscription not found")
    return subscription


@app.post("/users/reset-password")
def request_password_reset(email: str = Query(...), db: Session = Depends(get_db)):
    user = crud.get_user_by_email(db, email=email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    reset_token = crud.create_password_reset_token(email=email)
    # Here you would send the reset_token to the user's email
    return {"msg": "Password reset token sent", "token": reset_token}


@app.post("/reset-password/")
def reset_password(reset: schemas.PasswordReset, db: Session = Depends(get_db)):
    email = crud.verify_password_reset_token(reset.token)
    if email is None:
        raise HTTPException(status_code=400, detail="Invalid token")
    user = crud.reset_password(db, email=email, new_password=reset.new_password)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"msg": "Password reset successful"}


@app.post("/token", response_model=schemas.Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    user = crud.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/subscriptions/", response_model=schemas.Subscription)
def create_subscription(
    subscription: schemas.SubscriptionBase, db: Session = Depends(get_db)
):
    db_subscription = crud.create_subscription(db=db, subscription=subscription)
    if db_subscription is None:
        raise HTTPException(status_code=400, detail="Subscription creation failed")
    return db_subscription


@app.post("/plans/", response_model=schemas.Plan)
def create_plan(plan: schemas.PlanBase, db: Session = Depends(get_db)):
    if plan.renewal_period == 0:
        raise HTTPException(status_code=422, detail="Invalid renewal period")
    return crud.create_plan(db=db, plan=plan)


@app.get("/plans/", response_model=List[schemas.Plan])
def read_plan(db: Session = Depends(get_db)):
    db_plan = crud.get_plan(db)
    return db_plan


@app.put("/plans/{plan_id}", response_model=schemas.Plan)
def update_plan(plan_id: int, plan: schemas.PlanBase, db: Session = Depends(get_db)):
    db_plan = crud.update_plan(db=db, plan_id=plan_id, plan=plan)
    if db_plan is None:
        raise HTTPException(status_code=404, detail="Plan not found")
    return db_plan


@app.delete("/plans/{plan_id}", response_model=schemas.Plan)
def delete_plan(plan_id: int, db: Session = Depends(get_db)):
    db_plan = crud.delete_plan(db=db, plan_id=plan_id)
    if db_plan is None:
        raise HTTPException(status_code=404, detail="Plan not found")
    return db_plan


@app.get("/plans/{plan_id}", response_model=schemas.Plan)
def read_plan(plan_id: int, db: Session = Depends(get_db)):
    db_plan = crud.get_specific_plan(db, plan_id=plan_id)
    if db_plan is None:
        raise HTTPException(status_code=404, detail="Plan not found")
    return db_plan
