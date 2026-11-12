from typing import Annotated
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer

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
    
    # On s'attend à ce que le payload contienne sub, full_name, et role
    return {
        "username": payload.get("sub"),
        "full_name": payload.get("full_name"),
        "role": payload.get("role"),
    }


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
