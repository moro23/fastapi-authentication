from sqlalchemy import Boolean, Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from core.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    email = Column(String(255), unique=True, index=True)
    hashed_password = Column(String(255),nullable=True)
    reset_password_token = Column(String(255), nullable=True)

  