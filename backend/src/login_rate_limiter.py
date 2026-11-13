"""
Protection anti brute-force du login.

Compte les échecs par nom d'utilisateur et par adresse IP sur une fenêtre
glissante. Au-delà du seuil, le login est bloqué temporairement (HTTP 429).
Stockage en mémoire : suffisant pour une instance unique du prototype.
"""

import threading
import time
from collections import defaultdict, deque


class LoginRateLimiter:
    def __init__(self, max_failures: int, window_seconds: int, clock=time.monotonic):
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self._clock = clock
        self._failures: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    @staticmethod
    def _keys(username: str, client_ip: str) -> list[str]:
        return [f"user:{username.strip().lower()}", f"ip:{client_ip}"]

    def _prune(self, key: str, now: float) -> deque:
        attempts = self._failures[key]
        while attempts and now - attempts[0] >= self.window_seconds:
            attempts.popleft()
        return attempts

    def retry_after(self, username: str, client_ip: str) -> int:
        """Secondes à attendre avant de pouvoir réessayer (0 = autorisé)."""
        now = self._clock()
        wait = 0
        with self._lock:
            for key in self._keys(username, client_ip):
                attempts = self._prune(key, now)
                if len(attempts) >= self.max_failures:
                    wait = max(wait, int(self.window_seconds - (now - attempts[0])) + 1)
        return wait

    def record_failure(self, username: str, client_ip: str) -> None:
        now = self._clock()
        with self._lock:
            for key in self._keys(username, client_ip):
                self._prune(key, now).append(now)

    def record_success(self, username: str) -> None:
        # Un login réussi efface les échecs du compte (pas ceux de l'IP).
        with self._lock:
            self._failures.pop(f"user:{username.strip().lower()}", None)
