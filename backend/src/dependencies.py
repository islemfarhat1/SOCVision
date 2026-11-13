import hmac
import sqlite3
from typing import Annotated
from fastapi import Depends, Header, HTTPException
from fastapi.security import OAuth2PasswordBearer

from config import settings

from src.security import decode_token

# Rôles de la plateforme (SOC L3 retiré du périmètre : l'investigation est faite par le L2)
VALID_ROLES = frozenset({"SOC_L1", "SOC_L2", "MANAGER", "ADMIN"})

# URL de la route de login (uniquement pour la documentation OpenAPI)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> dict:
    """
    Dépendance FastAPI pour récupérer et décoder le token JWT.
    Retourne les informations de l'utilisateur sous forme de dictionnaire.
    """
    payload = decode_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    # The account is read from the database on every request, so a role change or a
    # deactivation applies immediately instead of when the 8-hour token expires.
    connection = sqlite3.connect(settings.DATABASE_PATH)
    row = connection.execute(
        "SELECT username, full_name, role, disabled FROM users WHERE username = ?", (payload.get("sub"),)
    ).fetchone()
    connection.close()
    if row is None or row[3]:
        raise HTTPException(status_code=401, detail="Account disabled or removed")

    return {"username": row[0], "full_name": row[1], "role": row[2]}


def require_role(*allowed_roles: str):
    """
    Générateur de dépendance pour restreindre l'accès à certains rôles.
    Utilisation: Depends(require_role("MANAGER", "ADMIN"))
    """
    unknown = set(allowed_roles) - VALID_ROLES
    if unknown:
        raise ValueError(f"Rôle(s) inconnu(s) dans require_role: {sorted(unknown)}")

    def role_dependency(current_user: Annotated[dict, Depends(get_current_user)]):
        if current_user.get("role") not in allowed_roles:
            raise HTTPException(status_code=403, detail="Not enough privileges")
        return current_user
    return role_dependency



def verify_webhook_token(x_webhook_token: Annotated[str | None, Header()] = None) -> None:
    """
    Authentifie les appels du webhook Wazuh avec un secret partagé.
    Refuse tout si aucun secret n'est configuré (fail closed).
    """
    expected = settings.WAZUH_WEBHOOK_TOKEN
    if not expected:
        raise HTTPException(status_code=503, detail="Webhook disabled: WAZUH_WEBHOOK_TOKEN is not configured")
    if not x_webhook_token or not hmac.compare_digest(x_webhook_token, expected):
        raise HTTPException(status_code=401, detail="Invalid webhook token")
