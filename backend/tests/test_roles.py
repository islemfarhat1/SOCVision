"""Tests du modèle de rôles (SOC L1 / SOC L2 / Manager / Admin)."""

import sqlite3

import pytest

from src.database.database_manager import DatabaseManager
from src.dependencies import VALID_ROLES, require_role


def test_valid_roles_do_not_include_l3():
    assert VALID_ROLES == {"SOC_L1", "SOC_L2", "MANAGER", "ADMIN"}


def test_require_role_rejects_unknown_role_name():
    with pytest.raises(ValueError):
        require_role("SOC_MANAGER")


def test_seed_has_no_l3_user(tmp_path):
    db_path = tmp_path / "soc.db"
    DatabaseManager(db_path=str(db_path))
    roles = {r[0] for r in sqlite3.connect(db_path).execute("SELECT role FROM users")}
    assert roles <= VALID_ROLES


def test_existing_l3_user_is_removed_on_startup(tmp_path):
    db_path = tmp_path / "soc.db"
    DatabaseManager(db_path=str(db_path))
    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO users (username, full_name, role) VALUES ('old.l3', 'Old L3', 'SOC_L3')")
    conn.commit()
    conn.close()

    DatabaseManager(db_path=str(db_path))
    count = sqlite3.connect(db_path).execute("SELECT COUNT(*) FROM users WHERE role = 'SOC_L3'").fetchone()[0]
    assert count == 0
