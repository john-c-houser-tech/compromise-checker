"""Scheduled checks: `checker run` (collect, analyze, report and purge what
has expired, in one pass, unattended when a timer starts it) and
`checker schedule` (the timer itself: a systemd user timer on Linux, a
launchd agent on macOS).

A run asks nothing: a host that would need a prompt (a password typed in,
a key file with a passphrase, no SSH agent) is refused before anything is
collected. The AI advisor is never asked. When a host's band rises, a new
high or critical finding appears, or a host couldn't be collected or
analysed, the run prints it and, if `notify_command` is set, hands a short
summary to that command (host names, bands, the new findings' titles and
the report's path; no evidence)."""

import asyncio
import fcntl
import os
import plistlib
import shlex
import subprocess
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import asyncssh

from checker.evidence import EvidenceError

BANDS = ("Low", "Medium", "High", "Critical")
SERIOUS = ("high", "critical")
# The run's exit status: the worst band analysed, so a timer's log shows
# trouble; a step that failed shows when nothing worse did.
EXIT_BAND = {"Low": 0, "Medium": 10, "High": 11, "Critical": 12}
EXIT_FAILED = 1
EXIT_SETUP = 2  # nothing was collected: unattended problems, no key, bad settings
EXIT_BUSY = 3  # another run holds the lock
NOTIFY_SECONDS = 120
UNIT = "compromise-checker"
LAUNCHD_LABEL = "com.nouriloop.compromise-checker"


class Busy(Exception):
    """Another `checker run` is in progress."""


@contextmanager
def run_lock(base: Path) -> Iterator[None]:
    """One run at a time: a second one started while the first is still
    going (a slow host, a timer firing twice) stops at once."""
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(base / "run.lock", os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Busy("another `checker run` is in progress") from None
        yield
    finally:
        os.close(fd)


def unattended_problems(hosts: list, environ: dict[str, str] | None = None) -> list[str]:
    """What would stop an unattended run at a prompt, per host, before
    anything is collected. (An agent that asks for its key's passphrase
    can't be seen from here: the docs say to use a key already unlocked.)"""
    environ = os.environ if environ is None else environ
    problems = []
    for host in hosts:
        if host.needs_password() and host.password_source != "keyring":  # noqa: S105
            what = "logs in with a password" if host.auth == "password" else "uses sudo's password"
            problems.append(
                f"{host.name} {what} typed at a prompt: keep it in the OS keyring"
                " (password_source keyring), or use a key and NOPASSWD sudo"
            )
        if host.auth == "agent" and not environ.get("SSH_AUTH_SOCK"):
            problems.append(
                f"{host.name} logs in with the SSH agent, and there is none (SSH_AUTH_SOCK unset)"
            )
        if host.auth == "key":
            problem = _key_problem(host.key_path)
            if problem:
                problems.append(f"{host.name}'s key {host.key_path}: {problem}")
    return problems


def _key_problem(path: str | None) -> str | None:
    if not path:
        return "no key file is named"
    try:
        asyncssh.read_private_key(Path(path).expanduser())
    except asyncssh.KeyImportError as exc:
        if "passphrase" in str(exc).lower():
            return "it has a passphrase, which an unattended run can't type"
        return f"it can't be read ({exc})"
    except OSError as exc:
        return f"it can't be read ({exc.strerror or exc})"
    return None


def unattended_password(host) -> str:
    """Passwords for an unattended run: from the keyring, never a prompt."""
    from checker.credentials import password_for

    if host.password_source != "keyring":  # noqa: S105 - a source name
        raise RuntimeError("an unattended run doesn't ask for passwords")
    return password_for(host)


# --- What changed since the last analysis ------------------------------------------------


def _identity_of(finding: dict[str, Any]) -> tuple:
    """The same finding in two analyses: its check and what it is about."""
    entities = tuple(sorted(finding.get("entities") or []))
    return (finding.get("check"), finding.get("variant"), entities or finding.get("title"))


def _in_effect(assessment: dict[str, Any] | None) -> list[dict[str, Any]]:
    return [f for f in (assessment or {}).get("findings") or [] if not f.get("suppressed_by")]


def _band(assessment: dict[str, Any] | None) -> str | None:
    return ((assessment or {}).get("score") or {}).get("band")


def alerts(host: str, before: dict | None, after: dict) -> list[str]:
    """Lines worth someone's attention: the band rose (a host's first
    analysis counts from Low), or a high or critical finding appeared
    that the last analysis didn't have in effect."""
    from checker.report import visible

    lines = []
    old, new = _band(before) or "Low", _band(after)
    if new in BANDS and BANDS.index(new) > BANDS.index(old if old in BANDS else "Low"):
        probability = (after.get("score") or {}).get("probability")
        shown = f" ({probability:.1%})" if isinstance(probability, (int, float)) else ""
        lines.append(f"{host}: {old} to {new}{shown}")
    seen = {_identity_of(f) for f in _in_effect(before)}
    for finding in _in_effect(after):
        if finding.get("band") in SERIOUS and _identity_of(finding) not in seen:
            lines.append(f"{host}: new {finding['band']}: {visible(finding.get('title'), 200)}")
    return lines


def latest_assessment(store, host: str, identity) -> dict[str, Any] | None:
    """The host's latest stored analysis, before this run adds one."""
    from checker.assess import load_assessment
    from checker.baseline import usable_bundles

    for row in reversed(usable_bundles(store, host)):
        try:
            found = load_assessment(store, row["id"], identity)
        except (EvidenceError, OSError, ValueError):
            return None  # unreadable: compared with nothing, so all serious ones show
        if found is not None:
            return found
    return None


def summary(alerting: list[str], report: Path | None) -> str:
    """What the notify command reads: a subject line, then the lines."""
    hosts = {line.split(":", 1)[0] for line in alerting}
    text = f"Compromise Checker: {len(hosts)} host(s) need a look\n\n" + "\n".join(alerting)
    if report is not None:
        text += f"\n\nReport: {report}"
    return text + "\n"


def notify(command: str, text: str, timeout: float = NOTIFY_SECONDS) -> str | None:
    """Run the organization's notify command with `text` on its input. No
    shell: the command is split into words. Returns why it failed, if it did."""
    try:
        done = subprocess.run(  # noqa: S603 - the organization's own command
            shlex.split(command),
            input=text,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return f"it didn't finish within {timeout:.0f} seconds"
    except (OSError, ValueError) as exc:
        return str(exc)
    if done.returncode != 0:
        said = (done.stderr or done.stdout or "").strip().splitlines()
        return f"it exited with status {done.returncode}" + (f": {said[-1][:200]}" if said else "")
    return None


# --- One run ------------------------------------------------------------------------------


@dataclass
class HostResult:
    host: str
    collected: str  # the collection's status
    band: str | None = None
    probability: float | None = None
    problem: str | None = None
    alerts: list[str] = field(default_factory=list)


@dataclass
class RunResult:
    hosts: list[HostResult]
    report: Path | None = None
    problems: list[str] = field(default_factory=list)  # not tied to one host
    notified: str | None = None  # why the notify command failed, if it did

    @property
    def alerting(self) -> list[str]:
        return [line for h in self.hosts for line in h.alerts]

    def exit_status(self) -> int:
        bands = [h.band for h in self.hosts if h.band in BANDS]
        worst = max(bands, key=BANDS.index) if bands else "Low"
        failed = self.problems or self.notified or any(h.problem for h in self.hosts)
        return EXIT_BAND[worst] or (EXIT_FAILED if failed else 0)


def run(
    base: Path,
    config,
    hosts: list,
    identity,
    inventory,
    *,
    unattended: bool,
    days: int = 30,
    parallel: int = 5,
    say: Callable[[str], None] = print,
    collect: Callable | None = None,
) -> RunResult:
    """Collect, analyze, report and purge what has expired; alert on what
    got worse. Takes the run lock; raises Busy if another run holds it."""
    from checker.assess import analyze, prior_for
    from checker.baseline import USABLE
    from checker.collect import collect_hosts
    from checker.credentials import password_for
    from checker.evidence import Store, database_file
    from checker.report import write_report
    from checker.whitelist import WhitelistError
    from checker.whitelist import for_host as whitelist_for_host

    collect = collect or collect_hosts
    with run_lock(base):
        store = Store(database_file(base))
        try:
            before = {h.name: latest_assessment(store, h.name, identity) for h in hosts}
            outcomes = asyncio.run(
                collect(
                    base,
                    config,
                    hosts,
                    days=days,
                    parallel=parallel,
                    password_provider=unattended_password if unattended else password_for,
                )
            )
            by_host = {o.host: o for o in outcomes}
            results, analysed = [], []
            for host in hosts:
                outcome = by_host.get(host.name)
                status = outcome.status if outcome else "not run"
                result = HostResult(host.name, status)
                results.append(result)
                if outcome is None or status not in USABLE:
                    why = (outcome.error if outcome else None) or status
                    result.problem = f"not collected ({why})"
                    result.alerts.append(f"{host.name}: {result.problem}")
                    continue
                try:
                    whitelist = whitelist_for_host(base, host.name, inventory)
                    assessment = analyze(
                        store,
                        host.name,
                        identity,
                        config.recipients,
                        outcome.bundle_id,
                        prior_for(host.name, config, inventory),
                        whitelist,
                    )
                except (EvidenceError, WhitelistError, OSError) as exc:
                    result.problem = f"not analysed ({exc})"
                    result.alerts.append(f"{host.name}: {result.problem}")
                    continue
                analysed.append(host.name)
                result.band = _band(assessment)
                result.probability = (assessment.get("score") or {}).get("probability")
                result.alerts += alerts(host.name, before.get(host.name), assessment)
                if outcome.error:
                    result.problem = f"collected in part ({outcome.error})"
            run_result = RunResult(results)
            if analysed:
                try:
                    run_result.report = write_report(
                        store,
                        analysed,
                        identity,
                        config.recipients,
                        base / "reports",
                        priors=lambda name: prior_for(name, config, inventory),
                        whitelists=lambda name: _whitelist_or_none(base, name, inventory),
                        advisor_enabled=config.advisor.enabled,
                    )
                except (EvidenceError, OSError) as exc:
                    run_result.problems.append(f"the report couldn't be written ({exc})")
            run_result.problems += _purge_expired(store, base, config, inventory, say)
        finally:
            store.close()
    if run_result.alerting and config.notify_command:
        run_result.notified = notify(
            config.notify_command, summary(run_result.alerting, run_result.report)
        )
    return run_result


def _whitelist_or_none(base: Path, host: str, inventory):
    from checker.whitelist import WhitelistError
    from checker.whitelist import for_host as whitelist_for_host

    try:
        return whitelist_for_host(base, host, inventory)
    except WhitelistError:
        return None


def _purge_expired(store, base: Path, config, inventory, say) -> list[str]:
    """`checker purge --expired --yes`, as part of the run (policy §8)."""
    from checker.purge import execute, leftovers
    from checker.purge import plan as purge_plan

    names = {h.name for h in inventory.hosts}
    if not names:
        return ["nothing purged: the inventory is empty, and expiry keeps inventoried baselines"]
    try:
        chosen = purge_plan(store, base, names, config.retention_days, expired=True)
        if chosen.outside:
            return ["nothing purged: some bundles are stored outside the evidence folder"]
        if not chosen.bundles and not leftovers(store, base):
            return []
        outcome = execute(store, base, chosen)
    except (EvidenceError, OSError, ValueError) as exc:
        return [f"the expired evidence couldn't be purged ({exc})"]
    say(f"Purged {outcome.counts['bundles']} expired bundle(s).")
    return [f"couldn't delete {path} ({reason})" for path, reason in outcome.failed]


# --- The timer ----------------------------------------------------------------------------


def _systemd_word(word: str) -> str:
    """One word of a systemd ExecStart= or Environment= line."""
    escaped = word.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
    return f'"{escaped.replace("$", "$$")}"'


def command_line() -> list[str]:
    """The run the timer starts: this Python, this installation."""
    return [sys.executable, "-m", "checker", "run", "--all", "--unattended"]


def timer_environment(base: Path, hosts: list, environ: dict[str, str] | None = None) -> dict:
    """What the timer's run needs from this environment: the tool's home
    (so it doesn't depend on XDG variables a timer may not have) and, for
    hosts that log in with the SSH agent, the agent's socket."""
    environ = os.environ if environ is None else environ
    env = {"CHECKER_HOME": str(base)}
    if any(h.auth == "agent" for h in hosts) and environ.get("SSH_AUTH_SOCK"):
        env["SSH_AUTH_SOCK"] = environ["SSH_AUTH_SOCK"]
    return env


def systemd_units(at: tuple[int, int], env: dict[str, str]) -> dict[str, str]:
    hour, minute = at
    lines = [f"Environment={_systemd_word(f'{k}={v}')}" for k, v in sorted(env.items())]
    service = "\n".join(
        [
            "[Unit]",
            "Description=Compromise Checker: scheduled run (collect, analyze, report)",
            "",
            "[Service]",
            "Type=oneshot",
            *lines,
            "ExecStart=" + " ".join(_systemd_word(w) for w in command_line()),
            # Exit statuses 10-12 are the worst band, not a failure to run.
            "SuccessExitStatus=10 11 12",
            "Nice=10",
            "",
        ]
    )
    timer = "\n".join(
        [
            "[Unit]",
            "Description=Compromise Checker: daily scheduled run",
            "",
            "[Timer]",
            f"OnCalendar=*-*-* {hour:02d}:{minute:02d}:00",
            "Persistent=true",
            "",
            "[Install]",
            "WantedBy=timers.target",
            "",
        ]
    )
    return {f"{UNIT}.service": service, f"{UNIT}.timer": timer}


def launchd_plist(at: tuple[int, int], env: dict[str, str], log: Path) -> bytes:
    hour, minute = at
    return plistlib.dumps(
        {
            "Label": LAUNCHD_LABEL,
            "ProgramArguments": command_line(),
            "EnvironmentVariables": env,
            "StartCalendarInterval": {"Hour": hour, "Minute": minute},
            "StandardOutPath": str(log),
            "StandardErrorPath": str(log),
            "ProcessType": "Background",
        }
    )


def parse_time(text: str) -> tuple[int, int]:
    try:
        hour, minute = (int(part) for part in text.split(":"))
    except ValueError:
        raise ValueError(f"not a time of day: {text!r} (use HH:MM)") from None
    if not (0 <= hour < 24 and 0 <= minute < 60):
        raise ValueError(f"not a time of day: {text!r} (use HH:MM)")
    return hour, minute


@dataclass
class Placement:
    """Where this system keeps the timer, and how it is started and stopped."""

    files: dict[Path, bytes]
    start: list[list[str]]
    stop: list[list[str]]
    logs: str


def placement(
    platform: str, at: tuple[int, int], env: dict[str, str], base: Path, user_home: Path
) -> Placement:
    if platform == "darwin":
        path = user_home / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"
        log = base / "logs" / "run.log"
        domain = f"gui/{os.getuid()}"
        return Placement(
            {path: launchd_plist(at, env, log)},
            [["launchctl", "bootstrap", domain, str(path)]],
            [["launchctl", "bootout", f"{domain}/{LAUNCHD_LABEL}"]],
            str(log),
        )
    folder = Path(os.environ.get("XDG_CONFIG_HOME") or user_home / ".config") / "systemd" / "user"
    return Placement(
        {folder / name: text.encode() for name, text in systemd_units(at, env).items()},
        [
            ["systemctl", "--user", "daemon-reload"],
            ["systemctl", "--user", "enable", "--now", f"{UNIT}.timer"],
        ],
        [
            ["systemctl", "--user", "disable", "--now", f"{UNIT}.timer"],
            ["systemctl", "--user", "daemon-reload"],
        ],
        f"journalctl --user -u {UNIT}.service",
    )


def lingering(user: str) -> bool | None:
    """Whether systemd keeps this user's timers running while they are
    logged out (None: can't tell)."""
    try:
        done = subprocess.run(  # noqa: S603
            ["loginctl", "show-user", user, "--property=Linger"],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = done.stdout.strip()
    return value == "Linger=yes" if value.startswith("Linger=") else None
