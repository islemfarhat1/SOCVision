"""
Gestion des comptes par l'administrateur (rôle Admin : accès et configuration).

- Pas de suppression : un compte est désactivé, pour garder la traçabilité
  (tickets assignés, auteurs des rapports, journal d'audit).
- Garde-fous : pas de modification de son propre rôle ni de sa propre désactivation,
  et il reste toujours au moins un administrateur actif.
- Chaque action est inscrite au journal d'audit (jamais de mot de passe).
"""

from typing import Annotated, Literal, Optional

import bcrypt
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from src.database.database_manager import DatabaseManager
from src.dependencies import require_role

router = APIRouter(prefix="/admin", tags=["admin"])
db = DatabaseManager()

Admin = Annotated[dict, Depends(require_role("ADMIN"))]
Role = Literal["SOC_L1", "SOC_L2", "MANAGER", "ADMIN"]
Password = Field(min_length=10, max_length=128)


class UserCreate(BaseModel):
    username: str = Field(pattern=r"^[a-z0-9._-]{3,32}$")
    full_name: str = Field(min_length=2, max_length=80)
    role: Role
    password: str = Password


class UserUpdate(BaseModel):
    full_name: Optional[str] = Field(default=None, min_length=2, max_length=80)
    role: Optional[Role] = None
    disabled: Optional[bool] = None


class PasswordReset(BaseModel):
    password: str = Password


def _hash(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _existing(username: str) -> dict:
    user = db.get_user(username)
    if not user:
        raise HTTPException(status_code=404, detail=f"Unknown account {username}")
    return user


@router.get("/users")
def list_users(current_user: Admin):
    return [{**u, "disabled": bool(u["disabled"])} for u in db.list_users()]


@router.post("/users", status_code=201)
def create_user(payload: UserCreate, current_user: Admin):
    if db.get_user(payload.username):
        raise HTTPException(status_code=409, detail=f"The username {payload.username} is already taken")
    db.create_user(payload.username, payload.full_name.strip(), payload.role, _hash(payload.password))
    db.add_audit_event(current_user["username"], "USER_CREATED",
                       details={"username": payload.username, "role": payload.role})
    return {**db.get_user(payload.username), "disabled": False}


@router.patch("/users/{username}")
def update_user(username: str, payload: UserUpdate, current_user: Admin):
    user = _existing(username)
    is_self = username == current_user["username"]
    actor = current_user["username"]

    if payload.role is not None and payload.role != user["role"]:
        if is_self:
            raise HTTPException(status_code=400, detail="You cannot change your own role.")
        if user["role"] == "ADMIN" and not user["disabled"] and db.count_active_admins() <= 1:
            raise HTTPException(status_code=400, detail="At least one active administrator must remain.")

    if payload.disabled is not None and payload.disabled != bool(user["disabled"]):
        if is_self:
            raise HTTPException(status_code=400, detail="You cannot disable your own account.")
        if payload.disabled and user["role"] == "ADMIN" and db.count_active_admins() <= 1:
            raise HTTPException(status_code=400, detail="At least one active administrator must remain.")

    if payload.full_name is not None and payload.full_name.strip() != user["full_name"]:
        db.update_user(username, {"full_name": payload.full_name.strip()})
        db.add_audit_event(actor, "USER_RENAMED", details={"username": username, "to": payload.full_name.strip()})
    if payload.role is not None and payload.role != user["role"]:
        db.update_user(username, {"role": payload.role})
        db.add_audit_event(actor, "USER_ROLE_CHANGED", details={"username": username, "from": user["role"], "to": payload.role})
    if payload.disabled is not None and payload.disabled != bool(user["disabled"]):
        db.update_user(username, {"disabled": 1 if payload.disabled else 0})
        db.add_audit_event(actor, "USER_DISABLED" if payload.disabled else "USER_ENABLED", details={"username": username})

    updated = db.get_user(username)
    return {**updated, "disabled": bool(updated["disabled"])}


@router.post("/users/{username}/password", status_code=204)
def reset_password(username: str, payload: PasswordReset, current_user: Admin):
    _existing(username)
    db.update_user(username, {"password_hash": _hash(payload.password)})
    db.add_audit_event(current_user["username"], "PASSWORD_RESET", details={"username": username})


@router.get("/audit")
def account_events(current_user: Admin, limit: int = 30):
    return db.get_account_events(limit=max(1, min(limit, 200)))
