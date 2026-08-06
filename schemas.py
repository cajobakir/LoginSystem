from enum import Enum
from typing import Optional
from pydantic import BaseModel, EmailStr


# Enum definicija za uloge
class UserRole(str, Enum):
    ADMIN = "admin"
    USER = "user"
    MODERATOR = "moderator"


# Osnovna User šema
class UserBase(BaseModel):
    email: EmailStr


# Pydantic model za registraciju korisnika
class UserCreate(UserBase):
    password: str
    role: UserRole = UserRole.USER


# Model za prikaz u odgovoru
class UserResponse(UserBase):
    id: int
    is_active: bool
    role: UserRole

    class Config:
        from_attributes = True


# Model za vraćanje access i refresh tokena
class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


# Model za zahtjev refresh tokena
class RefreshTokenRequest(BaseModel):
    refresh_token: str


# Model za reset passworda
class PasswordResetRequest(BaseModel):
    email: EmailStr


# Model za confirmanje resetovanja passworda
class PasswordResetConfirm(BaseModel):
    reset_token: str
    new_password: str


# =====================================================================
#                          TASKS ŠEME
# =====================================================================


# Bazna šema za taskove
class TaskBase(BaseModel):
    title: str
    description: Optional[str] = None


# Šema za slanje podataka pri kreiranju novog taska
class TaskCreate(TaskBase):
    pass


# Šema za djelomičnu izmjenu taska (npr. promjena statusa ili naslova)
class TaskUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    is_completed: Optional[bool] = None


# Šema za prikaz taska u JSON odgovoru
class TaskResponse(TaskBase):
    id: int
    is_completed: bool
    owner_id: int  # Usklađeno sa models.py (owner_id umjesto user_id)

    class Config:
        from_attributes = True