import os
from datetime import datetime, timedelta, timezone
from typing import List
import jwt
from database import get_db
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from models import DBUser
from passlib.context import CryptContext
from schemas import UserRole
from sqlalchemy.orm import Session

# 1. Učitavanje varijabli iz .env fajla
load_dotenv()

# 2. Čitanje vrijednosti iz okruženja
SECRET_KEY = os.getenv("SECRET_KEY", "default_secret_key_if_missing")
ALGORITHM = os.getenv("ALGORITHM", "HS256")

ACCESS_TOKEN_EXPIRE_SECONDS = int(os.getenv("ACCESS_TOKEN_EXPIRE_SECONDS", 120))
REFRESH_TOKEN_EXPIRE_SECONDS = int(os.getenv("REFRESH_TOKEN_EXPIRE_SECONDS", 300))
RESET_TOKEN_EXPIRE_MINUTES = int(os.getenv("RESET_TOKEN_EXPIRE_MINUTES", 15))

# HTTP Bearer šema za Swagger i frontend
security_scheme = HTTPBearer()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Funkcija za hashiranje šifre
def hash_password(password: str) -> str:
    return pwd_context.hash(password)


# Verifikacija šifre
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


# Kreiranje access tokena
def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(
        seconds=ACCESS_TOKEN_EXPIRE_SECONDS
    )
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# Kreiranje refresh tokena
def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(
        seconds=REFRESH_TOKEN_EXPIRE_SECONDS
    )
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# Kreiranje reset tokena
def create_reset_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=RESET_TOKEN_EXPIRE_MINUTES
    )
    to_encode.update({"exp": expire, "type": "reset"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# Dohvatanje trenutno ulogovanog korisnika
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: Session = Depends(get_db),
) -> DBUser:
    token = credentials.credentials
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Neispravni identifikacijski podaci ili je token istekao.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        if payload.get("type") != "access":
            raise credentials_exception

        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token je istekao.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError:
        raise credentials_exception

    user = db.query(DBUser).filter(DBUser.email == email).first()
    if user is None:
        raise credentials_exception

    return user


# RBAC Provjera uloga (Dependency)
def require_roles(allowed_roles: List[UserRole]):
    def role_checker(current_user: DBUser = Depends(get_current_user)) -> DBUser:
        # Pretvaramo uloge u string form format radi pouzdanog poređenja
        user_role_val = (
            current_user.role.value
            if isinstance(current_user.role, UserRole)
            else str(current_user.role)
        )
        allowed_roles_vals = [
            r.value if isinstance(r, UserRole) else str(r)
            for r in allowed_roles
        ]

        if user_role_val not in allowed_roles_vals:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Nemate privilegije za pristup ovoj ruti. Potrebna rola: {allowed_roles_vals}",
            )
        return current_user

    return role_checker