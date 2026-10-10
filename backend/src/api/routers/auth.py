import sqlite3
from typing import Annotated
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel

from config.settings import DATABASE_PATH
from src.security import verify_password, create_access_token
from src.dependencies import get_current_user

router = APIRouter(prefix="/auth", tags=["auth"])


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
def login(credentials: LoginRequest):
    user = get_user_by_username(credentials.username)

    if not user or not verify_password(credentials.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

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