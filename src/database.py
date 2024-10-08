from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Update the database URL to use PostgreSQL
SQLALCHEMY_DATABASE_URL = "postgresql://app_user:<password>@localhost/app"

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
