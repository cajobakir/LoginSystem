from database import Base
from sqlalchemy import Boolean, Column, Enum as SQLEnum, Integer, String
from schemas import UserRole


# Kreiranje sqlalchemy user modela sa Enum ulogom
class DBUser(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    role = Column(SQLEnum(UserRole), default=UserRole.USER, nullable=False)