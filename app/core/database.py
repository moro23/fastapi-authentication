from sqlalchemy import create_engine, MetaData
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker


SQLALCHEMY_DATABASE_URL = "sqlite:///./users_auth.db"
# SQLALCHEMY_DATABASE_URL = "postgresql://user:password@postgresserver/db"

## creating a connection
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
## creating a session
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

## declaring a mapping
Base = declarative_base(metadata=MetaData(schema=None))

## creating db connection
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
