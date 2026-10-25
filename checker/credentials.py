"""Asking for passwords. They are kept in memory for one run and never stored
by the tool (security and privacy policy §6)."""

import getpass

from checker.inventory import Host

KEYRING_SERVICE = "compromise-checker"


def password_for(host: Host) -> str:
    """The password for `host`: from the OS keyring if configured, else asked."""
    if host.password_source == "keyring":  # noqa: S105 - a source name, not a password
        try:
            import keyring
        except ImportError as exc:
            raise RuntimeError(
                "password_source is 'keyring' but the keyring package is not installed"
                " (pip install 'checker[keyring]')"
            ) from exc
        password = keyring.get_password(KEYRING_SERVICE, f"{host.user}@{host.address}")
        if password is None:
            raise RuntimeError(
                f"no password in the keyring for service {KEYRING_SERVICE!r},"
                f" user {host.user}@{host.address}"
            )
        return password
    return getpass.getpass(f"Password for {host.user}@{host.address} ({host.name}): ")
