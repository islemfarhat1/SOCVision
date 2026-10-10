import sqlite3
from typing import Optional, Annotated
from fastapi import APIRouter, Query, Depends

from config.settings import DATABASE_PATH
from src.api.models import UserSchema
from src.dependencies import get_current_user

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=list[UserSchema])
def get_users(
    current_user: Annotated[dict, Depends(get_current_user)],
    role: Optional[str] = Query(None, description="Filtrer par rôle, ex: SOC_L1,SOC_L2")
):
    """Retourne la liste des analystes/utilisateurs, filtrable par rôle."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if role:
        roles = [r.strip() for r in role.split(",")]
        placeholders = ",".join("?" for _ in roles)
        cursor.execute(f"SELECT id, username, full_name, role FROM users WHERE role IN ({placeholders})", roles)
    else:
        cursor.execute("SELECT id, username, full_name, role FROM users")

    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows