"""Passwords' hashes, with Django's own upgrade of an old one turned off."""

from django.contrib.auth.hashers import PBKDF2PasswordHasher


class NoUpgradeWhileChecking(PBKDF2PasswordHasher):
    """Left to itself, Django rewrites an out-of-date hash after a right password, unconditionally
    and after a slow check, so it would undo a lock-out that landed during the check. Instead
    `accounts.upgrade_password_hash` does it, only if the hash is still the one that was checked."""

    def must_update(self, encoded: str) -> bool:
        return False

    def verify(self, password: str, encoded: str) -> bool:
        """Django evens out a wrong password's time only when an upgrade is due, which it now never
        thinks. Without this, an old hash would answer faster and show the account exists."""
        right = super().verify(password, encoded)
        if not right and out_of_date(encoded):
            self.harden_runtime(password, encoded)
        return right


def out_of_date(encoded: str) -> bool:
    return PBKDF2PasswordHasher().must_update(encoded)
