from enum import Enum
from pydantic import BaseModel, EmailStr


# Enum definicija za uloge
class UserRole(str, Enum):
    ADMIN = "admin"
    USER = "user"
    MODERATOR = "moderator"


# Pydantic model za registraciju korisnika
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    role: UserRole = UserRole.USER  # Podrazumijevana rola je "user"


# Model za prikaz u odgovoru
class UserResponse(BaseModel):
    id: int
    email: str
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