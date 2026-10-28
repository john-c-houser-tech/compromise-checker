"""The detection proof's judging (the servers are only in the real run)."""

import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).parent / "integration"
sys.path.insert(0, str(HERE))  # it imports readonly_proof beside it
_spec = importlib.util.spec_from_file_location("detection_proof", HERE / "detection_proof.py")
detection = importlib.util.module_from_spec(_spec)
sys.modules["detection_proof"] = detection
_spec.loader.exec_module(detection)


def finding(check, band, summary, title="t"):
    return {"check": check, "band": band, "summary": summary, "title": title}


def test_each_behaviour_needs_its_finding_at_its_band():
    expected = detection.expectations("SHA256:backdoor")
    findings = [
        finding("account.uid0", "high", "cc-toor has UID 0"),
        finding("ssh.authorized_keys", "high", "root: ssh-ed25519 SHA256:backdoor in /root/.ssh"),
        finding("persistence.changes", "medium", "/etc/cron.d/cc-proof"),
        finding("persistence.changes", "low", "/etc/systemd/system/cc-proof.timer"),  # too low
        finding("ssh.login", "medium", "root from 203.0.113.1"),  # unexplained
    ]
    found, missing, other = detection.judge(findings, expected)
    assert len(found) == 3
    assert any(m.startswith("a systemd timer added") and "saw: low" in m for m in missing)
    assert len(missing) == len(expected) - 3
    assert other == ["medium ssh.login: t — root from 203.0.113.1"]


def test_the_attacks_use_the_runs_backdoor_key():
    assert "{root_key}" in detection.ATTACKS
    assert detection.ATTACKS.count("fail ") >= 8  # each step says when it couldn't be done


def test_a_title_can_be_required_too():
    [want] = [e for e in detection.expectations("k") if e.check == "process.executable"]
    summary = "cc-sleep (pid 9): /root/cc-sleep (deleted)"
    scratch = finding("process.executable", "high", summary, "A process running from a scratch dir")
    deleted = finding("process.executable", "high", summary, "A process whose program was deleted")
    assert detection.judge([scratch], [want])[1] and not detection.judge([deleted], [want])[1]
