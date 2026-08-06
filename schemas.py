from pydantic import BaseModel, EmailStr


# pydantic model za usera i mail
class UserCreate(BaseModel):
    email: EmailStr
    password: str


# model za prikaz u odgovoru
class UserResponse(BaseModel):
    id: int
    email: str
    is_active: bool

    class Config:
        from_attributes = True


# modle za vtacanje acces i refresh tokena useru
class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


#  model za zahtjev refresh tokena
class RefreshTokenRequest(BaseModel):
    refresh_token: str


#  model za reset passworda
class PasswordResetRequest(BaseModel):
    email: EmailStr

#model za confirmanje resetovanja passworda
class PasswordResetConfirm(BaseModel):
    reset_token: str
    new_password: str