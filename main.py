import jwt
from database import Base, engine, get_db
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from models import DBUser
from schemas import (
    PasswordResetConfirm,
    PasswordResetRequest,
    RefreshTokenRequest,
    TokenResponse,
    UserCreate,
    UserResponse,
    UserRole,
)
from security import (
    ALGORITHM,
    SECRET_KEY,
    create_access_token,
    create_refresh_token,
    create_reset_token,
    get_current_user,
    hash_password,
    require_roles,
    verify_password,
)
from sqlalchemy.orm import Session

app = FastAPI(title="LoginSistem sa Tokenima i RBAC-om")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)


# Endpoint za registraciju korisnika
@app.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(DBUser).filter(DBUser.email == user_data.email).first()
    if db_user:
        raise HTTPException(
            status_code=400, detail="Email je već registrovan."
        )

    hashed_pwd = hash_password(user_data.password)
    new_user = DBUser(
        email=user_data.email,
        hashed_password=hashed_pwd,
        role=user_data.role,  # Čuva se uloga proslijeđena u zahtjevu
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


# Login endpoint
@app.post("/login", response_model=TokenResponse)
def login(user_data: UserCreate, db: Session = Depends(get_db)):
    user = db.query(DBUser).filter(DBUser.email == user_data.email).first()

    if not user or not verify_password(user_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Neispravan email ili lozinka.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Vaš nalog je deaktiviran. Kontaktirajte podršku.",
        )

    access_token = create_access_token(data={"sub": user.email})
    refresh_token = create_refresh_token(data={"sub": user.email})

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


# Profil trenutno prijavljenog korisnika
@app.get("/me", response_model=UserResponse)
def get_my_profile(current_user: DBUser = Depends(get_current_user)):
    return current_user


# Refresh token endpoint
@app.post("/refresh", response_model=dict)
def refresh_token(request: RefreshTokenRequest):
    try:
        payload = jwt.decode(
            request.refresh_token, SECRET_KEY, algorithms=[ALGORITHM]
        )

        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=400, detail="Neodgovarajući tip tokena."
            )

        email = payload.get("sub")
        new_access_token = create_access_token(data={"sub": email})
        return {"access_token": new_access_token, "token_type": "bearer"}

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401, detail="Refresh token je istekao. Prijavite se ponovo."
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=401, detail="Nevalidan refresh token."
        )


# Forgot password
@app.post("/forgot-password")
def forgot_password(
    request: PasswordResetRequest, db: Session = Depends(get_db)
):
    user = db.query(DBUser).filter(DBUser.email == request.email).first()
    if not user:
        return {
            "poruka": "Ako email postoji u bazi, kod za reset je poslat."
        }

    reset_token = create_reset_token(data={"sub": user.email})

    return {
        "poruka": "Email sa instrukcijama je poslat.",
        "MOCK_EMAIL_RESET_TOKEN": reset_token,
    }


# Reset password
@app.post("/reset-password")
def reset_password(
    data: PasswordResetConfirm, db: Session = Depends(get_db)
):
    try:
        payload = jwt.decode(
            data.reset_token, SECRET_KEY, algorithms=[ALGORITHM]
        )

        if payload.get("type") != "reset":
            raise HTTPException(
                status_code=400, detail="Neodgovarajući reset token."
            )

        email = payload.get("sub")
        user = db.query(DBUser).filter(DBUser.email == email).first()
        if not user:
            raise HTTPException(
                status_code=404, detail="Korisnik nije pronađen."
            )

        user.hashed_password = hash_password(data.new_password)
        db.commit()

        return {"poruka": "Lozinka je uspješno izmijenjena!"}

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=400, detail="Reset token je istekao."
        )
    except jwt.PyJWTError:
        raise HTTPException(status_code=400, detail="Nevalidan reset token.")


# Deaktivacija naloga
@app.patch("/users/me/deactivate")
def deactivate_my_account(
    db: Session = Depends(get_db),
    current_user: DBUser = Depends(get_current_user),
):
    current_user.is_active = False
    db.commit()
    return {"poruka": "Vaš nalog je uspješno deaktiviran."}


# =====================================================================
#                          RBAC TEST RUTE
# =====================================================================


# Admin ruta (Samo za ulogu ADMIN)
@app.get(
    "/admin/dashboard",
    dependencies=[Depends(require_roles([UserRole.ADMIN]))],
)
def admin_dashboard():
    return {"poruka": "Dobrodošli na zaštićeni Admin Dashboard!"}


# Panel za Moderatore i Admina
@app.get(
    "/moderator/panel",
    dependencies=[
        Depends(require_roles([UserRole.ADMIN, UserRole.MODERATOR]))
    ],
)
def moderator_panel():
    return {"poruka": "Dobrodošli u Moderator Panel!"}