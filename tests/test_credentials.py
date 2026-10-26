import sys
import types

import pytest

from checker import credentials
from checker.inventory import Host


def test_keyring_entries_are_scoped_by_port(monkeypatch):
    stored = {
        (credentials.KEYRING_SERVICE, "scanner@192.0.2.1:2222"): "first",
        (credentials.KEYRING_SERVICE, "scanner@192.0.2.1:2223"): "second",
    }
    fake = types.SimpleNamespace(get_password=lambda service, user: stored.get((service, user)))
    monkeypatch.setitem(sys.modules, "keyring", fake)

    def host(port):
        return Host(
            name=f"h{port}",
            address="192.0.2.1",
            port=port,
            user="scanner",
            auth="password",
            password_source="keyring",
        )

    assert credentials.password_for(host(2222)) == "first"
    assert credentials.password_for(host(2223)) == "second"
    with pytest.raises(RuntimeError, match="scanner@192.0.2.1:22'"):
        credentials.password_for(host(22))
