import sqlite3
from typing import Annotated
import bcrypt
from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel, Field

from config.settings import DATABASE_PATH, LOGIN_MAX_FAILURES, LOGIN_LOCKOUT_SECONDS
from src.login_rate_limiter import LoginRateLimiter
from src.security import verify_password, create_access_token
from src.dependencies import get_current_user
from src.database.database_manager import DatabaseManager

router = APIRouter(prefix="/auth", tags=["auth"])

login_limiter = LoginRateLimiter(LOGIN_MAX_FAILURES, LOGIN_LOCKOUT_SECONDS)

# Hash factice : un utilisateur inexistant coûte le même temps bcrypt qu'un vrai,
# pour ne pas révéler par le temps de réponse quels comptes existent.
_DUMMY_HASH = bcrypt.hashpw(b"dummy-password", bcrypt.gensalt()).decode("utf-8")


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    full_name: str
    role: str


def get_user_by_username(username: str) -> dict | None:
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


@router.post("/login", response_model=LoginResponse)
def login(credentials: LoginRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"

    wait = login_limiter.retry_after(credentials.username, client_ip)
    if wait:
        raise HTTPException(
            status_code=429,
            detail="Too many failed login attempts. Try again later.",
            headers={"Retry-After": str(wait)},
        )

    user = get_user_by_username(credentials.username)
    password_hash = (user or {}).get("password_hash") or _DUMMY_HASH
    password_ok = verify_password(credentials.password, password_hash)

    if not user or not user.get("password_hash") or not password_ok:
        login_limiter.record_failure(credentials.username, client_ip)
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if user.get("disabled"):
        # Only revealed after a correct password, so it does not help guessing accounts.
        raise HTTPException(status_code=403, detail="This account is disabled. Contact your administrator.")

    login_limiter.record_success(credentials.username)

    token = create_access_token({
        "sub": user["username"],
        "full_name": user["full_name"],
        "role": user["role"],
    })

    return LoginResponse(
        access_token=token,
        full_name=user["full_name"],
        role=user["role"],
    )


@router.get("/me")
def get_me(current_user: Annotated[dict, Depends(get_current_user)]):
    """Vérifie le token dans le header Authorization et retourne les infos de l'utilisateur."""
    return current_user


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=10, max_length=128)


@router.post("/password", status_code=204)
def change_own_password(
    payload: PasswordChange,
    request: Request,
    current_user: Annotated[dict, Depends(get_current_user)],
):
    """
    Changement de son propre mot de passe. Le mot de passe actuel est exigé (une session
    restée ouverte ne suffit pas) et les erreurs comptent dans l'anti brute-force du login.
    """
    username = current_user["username"]
    client_ip = request.client.host if request.client else "unknown"

    wait = login_limiter.retry_after(username, client_ip)
    if wait:
        raise HTTPException(status_code=429, detail="Too many failed attempts. Try again later.",
                            headers={"Retry-After": str(wait)})

    user = get_user_by_username(username)
    if not user or not user.get("password_hash") or not verify_password(payload.current_password, user["password_hash"]):
        login_limiter.record_failure(username, client_ip)
        raise HTTPException(status_code=400, detail="The current password is incorrect.")
    if verify_password(payload.new_password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="The new password must be different from the current one.")

    db = DatabaseManager()
    db.update_user(username, {"password_hash": bcrypt.hashpw(payload.new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")})
    db.add_audit_event(username, "PASSWORD_CHANGED", details={"username": username})
    login_limiter.record_success(username)
