from database import Base
from schemas import UserRole
from sqlalchemy import Boolean, Column, Enum as SQLEnum, ForeignKey, Integer, String
from sqlalchemy.orm import relationship


# Kreiranje sqlalchemy user modela sa Enum ulogom
class DBUser(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    role = Column(SQLEnum(UserRole), default=UserRole.USER, nullable=False)

    # Relacija: Jedan korisnik ima više taskova
    tasks = relationship("DBTask", back_populates="owner", cascade="all, delete-orphan")


# Model za Taskove
class DBTask(Base):
    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(String, nullable=True)
    is_completed = Column(Boolean, default=False)

    # Strani ključ usklađen sa schemas.py (owner_id umjesto user_id)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Relacija nazad prema korisniku
    owner = relationship("DBUser", back_populates="tasks")


# Alijasi radi lakše kompatibilnosti sa main.py (models.User i models.Task)
User = DBUser
Task = DBTask