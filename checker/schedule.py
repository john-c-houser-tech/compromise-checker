"""Scheduled checks: `checker run` (collect, analyze, report and purge what
has expired, in one pass, unattended when a timer starts it) and
`checker schedule` (the timer itself: a systemd user timer on Linux, a
launchd agent on macOS).

An unattended run asks nothing: a host that would need a prompt (a password
typed in, a key file with a passphrase, no SSH agent) isn't collected, and
needs a look like any host that couldn't be. The AI advisor is never asked.
What needs a look (a band risen, a high or critical finding new or newly
that serious, a check newly failing, a host not collected or analysed, a
step of the run failing, a baseline purged) is printed and, if
`notify_command` is set, handed to that command as a short summary in the
tool's own words: host names, bands, check ids, finding titles and the
report's path, never text from a host. What each host looked like at the
last run, and alerts not yet delivered, are kept encrypted between runs,
so an alert the command couldn't deliver is sent with the next one."""

import asyncio
import contextlib
import fcntl
import json
import os
import plistlib
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any

import asyncssh

from checker.files import LockBusy, locked
from checker.transport import read_key_file

BANDS = ("Low", "Elevated", "High", "Critical")
FINDING_BANDS = ("info", "low", "medium", "high", "critical")
SERIOUS = ("high", "critical")
# The run's exit status: 1 when anything failed (the band is in the log and
# the summary), else the worst band analysed, so a timer's log shows it.
EXIT_BAND = {"Low": 0, "Elevated": 10, "High": 11, "Critical": 12}
EXIT_FAILED = 1
EXIT_SETUP = 2  # nothing was collected: no evidence key, unreadable settings
EXIT_BUSY = 3  # another run holds the lock
NOTIFY_SECONDS = 120
KEYRING_SECONDS = 60
STATE_FILE = "run-state.age"
EARLIER = "(from an earlier run) "
# Kept from the notify command: the advisor's keys, for one.
SECRET_VARIABLES = (
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "CHECKER_ADVISOR_API_KEY",
    "CHECKER_FALLBACK_API_KEY",
)
UNIT = "compromise-checker"
LAUNCHD_LABEL = "com.nouriloop.compromise-checker"


class Busy(Exception):
    """Another `checker run` is in progress."""


EXIT_STOPPED = 143  # by SIGTERM, as a shell reports it


class Stopped(SystemExit):
    """A run asked to stop, by SIGTERM. Not an Exception: no step's own trouble-handling should
    catch it and carry on."""


def stop_on_sigterm() -> None:
    """So that cleaning up happens, and locks and databases close properly. Main thread only."""

    def stop(*_) -> None:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)  # once: cleaning up mustn't be interrupted
        raise Stopped(EXIT_STOPPED)

    signal.signal(signal.SIGTERM, stop)


async def _cancelled_by_sigterm(work):
    """While a collection runs, stopping cancels it, so each host's evidence is sealed and recorded
    as far as it got: a file with no record of it is one a purge can't find."""
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()

    def stop_once() -> None:
        loop.remove_signal_handler(signal.SIGTERM)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        task.cancel()

    with contextlib.suppress(ValueError, RuntimeError, NotImplementedError):  # not the main thread
        loop.add_signal_handler(signal.SIGTERM, stop_once)
    return await work


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


# --- Unattended -----------------------------------------------------------------------------


def needs_typed_password(host) -> bool:
    return host.needs_password() and host.password_source != "keyring"  # noqa: S105


def host_problems(host, environ: dict[str, str] | None = None, typed: bool = False) -> list[str]:
    """What would stop an unattended run at a prompt on this host, `typed` if
    someone has already given its password. (An agent that asks for its key's
    passphrase can't be seen from here: the docs say to use a key already
    unlocked.)"""
    environ = os.environ if environ is None else environ
    problems = []
    if needs_typed_password(host) and not typed:
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


def host_problems_in_plain_words(host, environ: dict[str, str] | None = None) -> list[str]:
    """What stops a check started from a page, where a typed password can be given: the same
    conditions as `host_problems`, for someone who isn't at a command line."""
    environ = os.environ if environ is None else environ
    problems = []
    if host.auth == "agent" and not environ.get("SSH_AUTH_SOCK"):
        problems.append(
            "It logs in with an SSH agent, and this web server can't reach one. Give it a key file"
            " instead, or start the web server from a session that has an agent."
        )
    if host.auth == "key":
        problem = _key_problem(host.key_path)
        if problem:
            problems.append(f"Its key file can't be used: {problem}.")
    return problems


def unattended_in_plain_words(host, environ: dict[str, str] | None = None) -> list[str]:
    """What stops a scheduled check, where nobody is there to type: `host_problems`' conditions, for
    someone who isn't at a command line."""
    typing = (
        [
            "It needs a password typed. Give it a key file, or choose the keyring for its password"
            " (which has to be unlocked when the check runs)."
        ]
        if needs_typed_password(host)
        else []
    )
    return typing + host_problems_in_plain_words(host, environ)


def unattended_problems(hosts: list, environ: dict[str, str] | None = None) -> list[str]:
    return [problem for host in hosts for problem in host_problems(host, environ)]


def _key_problem(path: str | None) -> str | None:
    if not path:
        return "no key file is named"
    try:
        read_key_file(path)
    except asyncssh.KeyImportError as exc:
        if "passphrase" in str(exc).lower():
            return "it has a passphrase, which a check nobody is typing at can't enter"
        return f"it can't be read ({exc})"
    except OSError as exc:
        return f"it can't be read ({exc.strerror or exc})"
    return None


def unattended_password(host, timeout: float = KEYRING_SECONDS) -> str:
    """Passwords for an unattended run: from the keyring, never a prompt,
    and not waited for longer than `timeout` (a keyring that wants to be
    unlocked shows a dialog no one answers)."""
    from checker.credentials import password_for

    if host.password_source != "keyring":  # noqa: S105 - a source name
        raise RuntimeError("an unattended run doesn't ask for passwords")
    got: dict[str, Any] = {}

    def fetch() -> None:
        try:
            got["password"] = password_for(host)
        except Exception as exc:  # noqa: BLE001 - handed back below
            got["error"] = exc

    worker = threading.Thread(target=fetch, daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        raise RuntimeError(f"the keyring didn't answer within {timeout:.0f} seconds")
    if "error" in got:
        raise got["error"]
    return got["password"]


# --- What changed since the last run -------------------------------------------------------


def _identity_of(finding: dict[str, Any]) -> str:
    """The same finding in two analyses: its check, its kind and what it is
    about (a process's id left out: it changes when the process restarts).
    For a group listed only in part, its summary too, so a new member shows
    (a threat pack's detection's without its closing "(pack vN, …)": a new
    version of the pack is the same detection)."""
    entities = sorted(e for e in finding.get("entities") or [] if not e.startswith("pid:"))
    key = [finding.get("check"), finding.get("variant"), entities or finding.get("title")]
    if not finding.get("entities_complete", True):
        summary = str(finding.get("summary") or "")
        if finding.get("check") == "pack.detection":
            summary = summary.rpartition(" (")[0] or summary
        key.append(summary)
    return json.dumps(key)


def _band(assessment: dict[str, Any] | None) -> str | None:
    return ((assessment or {}).get("score") or {}).get("band")


# A pack's exposure, from least to most to look at (checker.packs.exposure's
# statuses), and how the summary says it.
EXPOSED = {
    "fixed": "exposed while the threat was active, fixed since",
    "can't judge": "can't be judged, so counted as exposed",
    "vulnerable": "vulnerable now",
}
_EXPOSURE_RANK = list(EXPOSED)


def _exposed(assessment: dict[str, Any]) -> tuple[dict[str, str], set[str]]:
    """The packs a host was exposed to, with each one's status, and the
    packs whose exposure couldn't be judged at all (a package listing
    collected in part, none of the pack's packages seen): those are gaps,
    neither news nor a reason to forget what was known."""
    if "exposures" not in assessment:  # analysed before exposures were kept
        return {str(r.get("pack")): str(r.get("status")) for r in _raised_by(assessment)}, set()
    exposed, unjudged = {}, set()
    for item in assessment.get("exposures") or []:
        if not isinstance(item, dict):
            continue
        if not item.get("judged", True):
            unjudged.add(str(item.get("pack")))
        elif item.get("share") and item.get("status") in EXPOSED:
            exposed[str(item.get("pack"))] = item["status"]
    return exposed, unjudged


def remembered(
    assessment: dict[str, Any] | None, before: dict[str, Any] | None = None
) -> dict[str, Any] | None:
    """What a later run compares with: the band, each finding in effect
    with its band, those a threat pack weighs, the checks that failed, and
    the packs the host was exposed to, with how (one the analysis couldn't
    judge keeps what `before` knew of it)."""
    if assessment is None:
        return None
    exposed, unjudged = _exposed(assessment)
    known = _exposure_memory(before)
    for pack in unjudged:
        if pack in known:
            exposed[pack] = known[pack]
    in_effect = [f for f in assessment.get("findings") or [] if not f.get("suppressed_by")]
    return {
        "band": _band(assessment),
        "exposed": exposed,
        "findings": {_identity_of(f): f.get("band") for f in in_effect},
        "weighed": sorted(_identity_of(f) for f in in_effect if f.get("raised_by_pack")),
        "failed": sorted(
            str(c.get("check"))
            for c in assessment.get("checks") or []
            if str(c.get("status", "")).startswith("failed")
        ),
    }


def _exposure_memory(before: dict[str, Any] | None) -> dict[str, str]:
    known = (before or {}).get("exposed") or {}
    if isinstance(known, list):  # an earlier form: ids only
        return {str(p): "vulnerable" for p in known}
    return {str(k): str(v) for k, v in known.items()} if isinstance(known, dict) else {}


def _raised_by(assessment: dict[str, Any]) -> list[dict[str, Any]]:
    """The packs whose exposure raised the prior (checker.assess._exposures)."""
    return [
        r for r in (assessment.get("score") or {}).get("raised_by") or [] if isinstance(r, dict)
    ]


def _rank(band: Any) -> int:
    return FINDING_BANDS.index(band) if band in FINDING_BANDS else -1


def alerts(host: str, before: dict | None, after: dict) -> list[str]:
    """What needs a look on a host analysed now, against what it looked like
    (remembered()): the band rose (a first analysis counts from Low), a
    high or critical finding is new or newly that serious, a threat pack's
    detection is new or more serious whatever its band (its own, or a
    core finding it newly weighs), the host is newly exposed to a pack's
    threat or more so (a pack added since finds it was; fixed, then can't
    judge, then vulnerable), a check newly failed. In the tool's own words
    and the packs': no text from the host."""
    from checker.report import visible

    lines = []
    old, new = (before or {}).get("band") or "Low", _band(after)
    old = old if old in BANDS else "Low"
    if new in BANDS and BANDS.index(new) > BANDS.index(old):
        probability = (after.get("score") or {}).get("probability")
        shown = f" ({probability:.1%})" if isinstance(probability, (int, float)) else ""
        lines.append(f"{host}: {old} to {new}{shown}")
    known = _exposure_memory(before)
    listed = [e for e in after.get("exposures") or [] if isinstance(e, dict)]
    versions = {str(e.get("pack")): e.get("version") for e in listed or _raised_by(after)}
    for pack, status in sorted(_exposed(after)[0].items()):
        was = known.get(pack)
        if was is None or _EXPOSURE_RANK.index(status) > _EXPOSURE_RANK.index(
            was if was in EXPOSED else "fixed"
        ):
            lines.append(
                f"{host}: exposed to threat pack {visible(pack, 80)}"
                f" v{visible(versions.get(pack), 10)} ({EXPOSED[status]})"
            )
    seen = (before or {}).get("findings") or {}
    if before is not None and "weighed" not in before:  # kept before weighing was: no news
        weighed = {_identity_of(f) for f in after.get("findings") or [] if f.get("raised_by_pack")}
    else:
        weighed = set((before or {}).get("weighed") or [])
    for finding in after.get("findings") or []:
        by_pack = finding.get("raised_by_pack")
        detection = finding.get("check") == "pack.detection" or bool(by_pack)
        if finding.get("suppressed_by") or (finding.get("band") not in SERIOUS and not detection):
            continue
        identity = _identity_of(finding)
        was = seen.get(identity)
        title = visible(finding.get("title"), 200)
        if finding.get("check") == "pack.detection":
            title += (
                f" (threat pack {visible(str(finding.get('variant') or '').partition('/')[0], 80)})"
            )
        elif by_pack:
            title += f" (weighed by threat pack {visible(by_pack, 120)})"
        if _rank(finding["band"]) > _rank(was):
            what = f"new {finding['band']}" if was is None else f"now {finding['band']} (was {was})"
            lines.append(f"{host}: {what}: {title}")
        elif by_pack and identity not in weighed:
            lines.append(f"{host}: newly weighed by a threat pack: {title}")
    failed_before = set((before or {}).get("failed") or [])
    for check in (remembered(after) or {}).get("failed") or []:
        if check not in failed_before:
            lines.append(f"{host}: check {visible(check, 80)} failed")
    return lines


def latest_assessment(store, host: str, identity) -> dict[str, Any] | None:
    """The host's latest stored analysis (for a host the run hasn't seen)."""
    from checker.assess import load_assessment
    from checker.baseline import usable_bundles

    for row in reversed(usable_bundles(store, host)):
        try:
            found = load_assessment(store, row["id"], identity)
        except Exception:  # noqa: BLE001 - unreadable: compared with nothing, so all show
            return None
        if found is not None:
            return found
    return None


def load_state(base: Path, identity) -> dict[str, Any]:
    """The last run's view of each host, and alerts not yet delivered."""
    from checker.evidence import open_text

    path = base / STATE_FILE
    try:
        state = json.loads(open_text(path.read_bytes(), identity) or "{}")
    except FileNotFoundError:
        return {}
    except Exception:  # noqa: BLE001 - unreadable: start again from the stored analyses
        return {}
    return state if isinstance(state, dict) else {}


def save_state(base: Path, state: dict[str, Any], recipients: list[str]) -> None:
    from checker.evidence import seal_text

    blob = seal_text(json.dumps(state), recipients) or b""
    fd, tmp = tempfile.mkstemp(dir=base, prefix=f".{STATE_FILE}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(blob)
        os.replace(tmp, base / STATE_FILE)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def summary(alerting: list[str], report: Path | None) -> str:
    """What the notify command reads: a subject line, then the lines."""
    text = f"Compromise Checker: {len(alerting)} thing(s) need a look\n\n" + "\n".join(alerting)
    if report is not None:
        text += f"\n\nReport: {report}"
        if report.suffix == ".age":
            text += f"\nTo read it: checker report --open {report}"
    return text + "\n"


def notify(command: str, text: str, timeout: float = NOTIFY_SECONDS) -> str | None:
    """Run the organization's notify command with `text` on its input. No
    shell: the command is split into words; the advisor's keys are kept
    from it. Its output goes to a file, so a program it leaves running in
    the background doesn't hold the run. Returns why it failed, if it did."""
    env = {k: v for k, v in os.environ.items() if k not in SECRET_VARIABLES}
    try:
        with tempfile.TemporaryFile("w+") as said:
            done = subprocess.run(  # noqa: S603 - the organization's own command
                shlex.split(command),
                input=text,
                text=True,
                stdout=said,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                env=env,
                check=False,
            )
            said.seek(0)
            last = said.read().strip().splitlines()
    except subprocess.TimeoutExpired:
        return f"it didn't finish within {timeout:.0f} seconds"
    except (OSError, ValueError) as exc:
        return str(exc)
    if done.returncode != 0:
        return f"it exited with status {done.returncode}" + (f": {last[-1][:200]}" if last else "")
    return None


# --- One run ------------------------------------------------------------------------------


@dataclass
class HostResult:
    host: str
    collected: str  # the collection's status
    band: str | None = None
    probability: float | None = None
    problem: str | None = None  # in detail, made safe to show; for the terminal and the log
    alerts: list[str] = field(default_factory=list)


@dataclass
class RunResult:
    hosts: list[HostResult]
    report: Path | None = None
    problems: list[str] = field(default_factory=list)  # not tied to one host, in detail
    run_alerts: list[str] = field(default_factory=list)  # not tied to one host
    earlier: list[str] = field(default_factory=list)  # alerts an earlier run couldn't deliver
    notified: str | None = None  # why the notify command failed, if it did

    @property
    def alerting(self) -> list[str]:
        return [*self.earlier, *(line for h in self.hosts for line in h.alerts), *self.run_alerts]

    def failed(self) -> bool:
        return bool(self.problems or self.notified or any(h.problem for h in self.hosts))

    def exit_status(self) -> int:
        if self.failed():
            return EXIT_FAILED
        bands = [h.band for h in self.hosts if h.band in BANDS]
        return EXIT_BAND[max(bands, key=BANDS.index)] if bands else 0


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
    environ: dict[str, str] | None = None,
    typed_passwords: dict[str, str] | None = None,
) -> RunResult:
    """Collect, analyze, report and purge what has expired; say what needs a
    look. Each step's trouble is caught and reported, so the later steps
    and the notification still happen. Raises Busy if another run holds the
    lock. `typed_passwords` are what someone gave for this run, by host, from
    the web interface: an unattended run uses them and asks for nothing."""
    from checker.assess import analyze, prior_for
    from checker.baseline import USABLE
    from checker.collect import collect_hosts
    from checker.credentials import password_for
    from checker.evidence import Store, database_file
    from checker.packs.choice import for_host
    from checker.packs.store import in_force
    from checker.report import visible, write_report
    from checker.whitelist import for_host as whitelist_for_host

    collect = collect or collect_hosts
    typed_passwords = typed_passwords or {}

    def given_or_unattended(host) -> str:
        return typed_passwords.get(host.name) or unattended_password(host)

    if unattended:
        provider = given_or_unattended if typed_passwords else unattended_password
    else:
        provider = password_for
    result = RunResult([])
    with run_lock(base):
        state = load_state(base, identity)
        seen = state.get("hosts") if isinstance(state.get("hosts"), dict) else {}
        result.earlier = [
            line if line.startswith(EARLIER) else EARLIER + line
            for line in state.get("pending") or []
            if isinstance(line, str)
        ]
        store = Store(database_file(base))
        pack_problems: list[str] = []
        try:
            # Read once for the run: every host is analysed with the packs
            # read then, those its rule applies (checker.packs.choice).
            found = in_force(base, config.packs.trusted_keys)
            packs_for = partial(for_host, config=config, inventory=inventory, found=found)
            pack_problems = found[1]
            for problem in pack_problems:
                result.problems.append(f"threat pack not applied: {visible(problem, 300)}")
            # Told when it starts or changes, not every run while it lasts
            # (the run's log and exit status still say it).
            if pack_problems and set(pack_problems) != set(state.get("pack_problems") or []):
                result.run_alerts.append(
                    f"{len(pack_problems)} threat pack(s) not applied (`checker packs list`)"
                )
            refused = {}
            if unattended:
                for host in hosts:
                    if problems := host_problems(host, environ, host.name in typed_passwords):
                        refused[host.name] = "; ".join(problems)
            todo = [h for h in hosts if h.name not in refused]
            before = {
                h.name: seen.get(h.name) or remembered(latest_assessment(store, h.name, identity))
                for h in todo
            }
            outcomes = []
            if todo:
                before_sigterm = signal.getsignal(signal.SIGTERM)
                try:
                    outcomes = asyncio.run(
                        _cancelled_by_sigterm(
                            collect(
                                base,
                                config,
                                todo,
                                days=days,
                                parallel=parallel,
                                password_provider=provider,
                            )
                        )
                    )
                except asyncio.CancelledError:
                    raise Stopped(EXIT_STOPPED) from None
                except Exception as exc:  # noqa: BLE001 - every host shows as not collected
                    result.problems.append(
                        f"collection failed ({type(exc).__name__}: {visible(str(exc), 300)})"
                    )
                finally:
                    if threading.current_thread() is threading.main_thread():
                        signal.signal(signal.SIGTERM, before_sigterm)  # asyncio's went with it
            by_host = {o.host: o for o in outcomes}
            analysed = []
            for host in hosts:
                outcome = by_host.get(host.name)
                item = HostResult(host.name, outcome.status if outcome else "not run")
                result.hosts.append(item)
                if host.name in refused:
                    item.collected = "refused"
                    item.problem = f"not collected: {visible(refused[host.name], 600)}"
                    item.alerts.append(f"{host.name}: not collected (it would need a prompt)")
                    continue
                if outcome is None or outcome.status not in USABLE:
                    # The status is the tool's word; the detail (a host's own
                    # error text, perhaps) stays out of the summary.
                    detail = visible((outcome.error if outcome else None) or "", 300)
                    item.problem = f"not collected ({item.collected})" + (
                        f": {detail}" if detail else ""
                    )
                    item.alerts.append(f"{host.name}: not collected ({item.collected})")
                    continue
                try:
                    assessment = analyze(
                        store,
                        host.name,
                        identity,
                        config.recipients,
                        outcome.bundle_id,
                        prior_for(host.name, config, inventory),
                        whitelist_for_host(base, host.name, inventory),
                        *packs_for(host.name),
                    )
                except Exception as exc:  # noqa: BLE001 - one host's trouble isn't the others'
                    item.problem = f"not analysed ({type(exc).__name__}: {visible(str(exc), 300)})"
                    item.alerts.append(f"{host.name}: not analysed ({type(exc).__name__})")
                    continue
                analysed.append(host.name)
                item.band = _band(assessment)
                item.probability = (assessment.get("score") or {}).get("probability")
                item.alerts += alerts(host.name, before.get(host.name), assessment)
                seen[host.name] = remembered(assessment, before.get(host.name))
                if outcome.status != "complete" or outcome.error:
                    item.problem = f"collected in part ({outcome.status})" + (
                        f": {visible(outcome.error, 300)}" if outcome.error else ""
                    )
                    item.alerts.append(f"{host.name}: collected in part ({outcome.status})")
            if analysed:
                try:
                    result.report = write_report(
                        store,
                        analysed,
                        identity,
                        config.recipients,
                        base / "reports",
                        priors=lambda name: prior_for(name, config, inventory),
                        whitelists=lambda name: _whitelist_or_none(base, name, inventory),
                        advisor_enabled=config.advisor.enabled,
                        packs=packs_for,
                    )
                except Exception as exc:  # noqa: BLE001 - the purge and the notice still happen
                    result.problems.append(
                        f"the report couldn't be written ({type(exc).__name__}:"
                        f" {visible(str(exc), 300)})"
                    )
                    result.run_alerts.append("the report couldn't be written")
            _purge_expired(store, base, config, inventory, say, result)
        except Stopped:
            # What this run found mustn't be lost to the next: it would compare against this run's
            # results and see nothing new to say.
            with contextlib.suppress(OSError):
                save_state(
                    base,
                    {"hosts": seen, "pending": result.alerting, "pack_problems": pack_problems},
                    config.recipients,
                )
            raise
        finally:
            store.close()
        pending: list[str] = []
        if result.alerting and config.notify_command:
            result.notified = notify(config.notify_command, summary(result.alerting, result.report))
            if result.notified:
                pending = result.alerting  # sent with the next run's
        try:
            save_state(
                base,
                {"hosts": seen, "pending": pending, "pack_problems": pack_problems},
                config.recipients,
            )
        except OSError as exc:
            result.problems.append(f"the run's state couldn't be kept ({exc})")
    return result


def _whitelist_or_none(base: Path, host: str, inventory):
    from checker.whitelist import WhitelistError
    from checker.whitelist import for_host as whitelist_for_host

    try:
        return whitelist_for_host(base, host, inventory)
    except WhitelistError:
        return None


def _purge_expired(store, base: Path, config, inventory, say, result: RunResult) -> None:
    """`checker purge --expired --yes` for the hosts in the inventory, as
    part of the run (policy §8). A baseline it takes needs a look: changes
    before the next one no longer show. Hosts no longer in the inventory
    (perhaps only paused) keep their evidence, baselines included, until a
    person runs the purge: their baselines have no protection from expiry,
    and a run shouldn't take them unasked."""
    from checker.purge import execute, leftovers
    from checker.purge import plan as purge_plan

    names = {h.name for h in inventory.hosts}
    if not names:
        result.problems.append(
            "nothing purged: the inventory is empty, and expiry keeps inventoried baselines"
        )
        return
    try:
        chosen = purge_plan(store, base, names, config.retention_days, expired=True, only=names)
        others = set(store.hosts()) - names
        waiting = (
            purge_plan(
                store, base, names, config.retention_days, expired=True, files=False, only=others
            ).bundles
            if others
            else []
        )
        if waiting:
            say(
                f"Note: {len(waiting)} expired bundle(s) of hosts not in the inventory are kept"
                " (with their baselines): `checker purge --expired` deletes them."
            )
        if chosen.outside:
            result.problems.append(
                "nothing purged: some bundles are stored outside the evidence folder"
            )
            result.run_alerts.append("the expired evidence couldn't be purged")
            return
        if not chosen.bundles and not leftovers(store, base):
            return
        outcome = execute(store, base, chosen)
    except Exception as exc:  # noqa: BLE001 - the notice still happens
        result.problems.append(f"the expired evidence couldn't be purged ({exc})")
        result.run_alerts.append("the expired evidence couldn't be purged")
        return
    say(f"Purged {outcome.counts['bundles']} expired bundle(s).")
    for host, what in sorted(chosen.baselines.items()):
        result.run_alerts.append(
            f"{host}: its expired baseline was purged; a newer bundle becomes its baseline"
            if what == "moved"
            else f"{host}: all its evidence had expired and was purged"
        )
    for path, reason in outcome.failed:
        result.problems.append(f"couldn't delete {path} ({reason})")
    if outcome.failed:
        result.run_alerts.append("some expired files couldn't be deleted")


def notify_crash(config, exc: BaseException) -> str | None:
    """A run that stopped on something unforeseen still tells someone."""
    if not config.notify_command:
        return None
    return notify(
        config.notify_command,
        summary([f"the scheduled run stopped: {type(exc).__name__}"], None),
    )


# --- The timer ----------------------------------------------------------------------------


# What systemd won't take in a path, or would read as its own syntax.
SYSTEMD_UNSAFE = re.compile(r"[\x00-\x1f\x7f\"'\\$`]")


def systemd_unsafe(env: dict[str, str]) -> list[str]:
    """The paths the timer would need that a systemd unit can't hold."""
    return [w for w in [*command_line(), *env.values()] if SYSTEMD_UNSAFE.search(w)]


def _systemd_word(word: str) -> str:
    """One word of a systemd ExecStart= or Environment= line (checked
    with systemd_unsafe() first; "%" is systemd's own, so doubled)."""
    return '"' + word.replace("%", "%%") + '"'


def command_line() -> list[str]:
    """The run the timer starts: this Python, this installation."""
    # -P: the timer's working directory isn't where Python looks for code.
    return [sys.executable, "-P", "-m", "checker", "run", "--all", "--unattended"]


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
            # Exit statuses 10-12 are the worst band, not a failure to run; 143 is being stopped.
            "SuccessExitStatus=10 11 12 143",
            # A run waiting on something forever would keep the timer from starting it again.
            "TimeoutStartSec=4h",
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


class InstallFailed(Exception):
    """Why the timer couldn't be set up or stopped. Its files are as they were before."""


TIMER_COMMAND_SECONDS = 60  # a hung systemctl mustn't hold a page, or the command, for ever


def _timer_command(command: list[str]) -> Any:
    try:
        return subprocess.run(  # noqa: S603
            command, capture_output=True, text=True, check=False, timeout=TIMER_COMMAND_SECONDS
        )
    except subprocess.TimeoutExpired:
        raise InstallFailed(f"`{' '.join(command)}` didn't finish") from None
    except OSError as exc:
        raise InstallFailed(f"`{' '.join(command)}` failed: {exc.strerror}") from None


class AnotherHome(InstallFailed):
    """The timer runs another copy of this tool, so it wasn't changed."""


TIMER_LOCK_SECONDS = 10


def _timer_lock(where: Placement):
    """Per user, as the timer is, whichever copy of this tool is asking: one change at a time, from
    looking at what's there to putting it back."""
    folder = next(iter(where.files)).parent
    return locked(folder / UNIT, wait=TIMER_LOCK_SECONDS)


def _put_back(
    where: Placement, earlier: dict[Path, bytes | None], was_on: bool | None, touched: bool
) -> None:
    """After a failed start: the files as they were, and the timer as it was, as far as that goes.
    It's best effort: what can't be restored shows on the next look at the timer. If nothing was
    asked of the scheduler yet, nothing is now, and one that was off is never switched on."""
    for path, content in earlier.items():
        with contextlib.suppress(OSError):
            if content is None:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(content)
    if not touched:
        return
    had_one = any(content is not None for content in earlier.values())
    if not had_one:
        steps = [] if sys.platform == "darwin" else where.stop
    elif was_on:
        steps = where.start
    else:
        steps = [] if sys.platform == "darwin" else where.start[:1]  # its files changed back
    for command in steps:
        with contextlib.suppress(InstallFailed):
            _timer_command(command)


def _refuse_another_home(base: Path) -> None:
    if timer_of_another_home(base):
        raise AnotherHome("the timer runs another copy of this tool")


def install(
    base: Path,
    at: tuple[int, int],
    hosts: list,
    say: Callable[[str], None] = lambda words: None,
    pause: Callable[[float], None] | None = None,
    only_this_home: bool = False,
) -> Placement:
    """Write the timer's files and start it, as `checker schedule install` and a page do. If it
    can't start, the files go back as they were: left there, they'd read as a timer that runs."""
    env = timer_environment(base, hosts)
    if sys.platform != "darwin" and (unsafe := systemd_unsafe(env)):
        raise InstallFailed(
            "a systemd unit can't hold these paths (quotes, backslashes, $, ` or control"
            " characters): " + ", ".join(repr(word) for word in unsafe)
        )
    where = placement(sys.platform, at, env, base, Path.home())
    try:
        with _timer_lock(where):
            if only_this_home:
                _refuse_another_home(base)
            _install_locked(base, where, say, pause or time.sleep)
    except LockBusy:
        raise InstallFailed("someone else is changing the timer: try again") from None
    return where


def _install_locked(base: Path, where: Placement, say, pause) -> None:
    try:
        earlier = {path: path.read_bytes() if path.exists() else None for path in where.files}
    except OSError as exc:
        raise InstallFailed(f"the timer's files can't be read: {exc.strerror}") from None
    was_on = timer_running()
    touched = False
    try:
        for path, content in where.files.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            say(f"Wrote {path}")
        if sys.platform == "darwin":
            (base / "logs").mkdir(exist_ok=True, mode=0o700)
            touched = True
            _timer_command(where.stop[0])  # a reload
        for command in where.start:
            touched = True
            # launchd may still be unloading the old agent: a few tries, a second apart.
            for _ in range(5 if sys.platform == "darwin" else 1):
                done = _timer_command(command)
                if done.returncode == 0:
                    break
                pause(1.0)
            if done.returncode != 0:
                raise InstallFailed(f"`{' '.join(command)}` failed: {(done.stderr or '').strip()}")
    except (InstallFailed, OSError) as exc:
        _put_back(where, earlier, was_on, touched)
        why = exc.strerror if isinstance(exc, OSError) else exc
        raise InstallFailed(f"{why} (the timer's files were put back as they were)") from None


_NOT_LOADED = (3, 113)  # launchctl: no such process, or not loaded


def remove_timer(base: Path, only_this_home: bool = False) -> tuple[list[Path], bool]:
    """Stop the timer and delete its files. Returns those it deleted, and whether a timer was
    running or there to stop. If it can't be stopped, the files stay: a timer that keeps running
    with nothing saying so is the worst outcome. Its files can be gone while it's still loaded, so
    the scheduler is asked, not just the folder."""
    where = placement(sys.platform, (3, 0), {}, base, Path.home())
    try:
        with _timer_lock(where):
            if only_this_home:
                _refuse_another_home(base)
            return _remove_locked(where)
    except LockBusy:
        raise InstallFailed("someone else is changing the timer: try again") from None


def _remove_locked(where: Placement) -> tuple[list[Path], bool]:
    present = [path for path in where.files if path.exists()]
    if not present and timer_running() is not True:
        return [], False
    stop, *after = where.stop  # stopped while its files are there; reloaded once they're gone
    done = _timer_command(stop)
    words = (done.stderr or "").strip()
    fine = (
        done.returncode == 0
        or (sys.platform == "darwin" and done.returncode in _NOT_LOADED)
        or "does not exist" in words
    )
    if not fine:
        raise InstallFailed(f"`{' '.join(stop)}` failed: {words}")
    for path in present:
        path.unlink()
    for command in after:
        with contextlib.suppress(InstallFailed):  # it is stopped: this only tidies up
            _timer_command(command)
    return present, True


def placement_exists(base: Path) -> bool:
    where = placement(sys.platform, (3, 0), {}, base, Path.home())
    return any(path.exists() for path in where.files)


def timer_time(base: Path) -> str | None:
    """The installed timer's time of day, HH:MM, if it's the daily one this tool writes; None if
    there's none, or a person changed it to something this can't state."""
    where = placement(sys.platform, (3, 0), {}, base, Path.home())
    for path in where.files:
        if path.suffix == ".plist" and path.exists():
            when = _plist(path).get("StartCalendarInterval")
            if isinstance(when, dict) and set(when) == {"Hour", "Minute"}:
                return f"{int(when['Hour']):02}:{int(when['Minute']):02}"
            return None
        if path.suffix == ".timer" and path.exists():
            try:
                text = path.read_text()
            except (OSError, UnicodeError):
                return None
            lines = [line.strip() for line in text.splitlines()]
            lines = [line for line in lines if line.startswith("On")]
            found = (
                re.fullmatch(r"OnCalendar=\*-\*-\* (\d\d):(\d\d):00", lines[0]) if lines else None
            )
            return f"{found[1]}:{found[2]}" if found and len(lines) == 1 else None
    return None


def _plist(path: Path) -> dict[str, Any]:
    try:
        found = plistlib.loads(path.read_bytes())
    except Exception:  # noqa: BLE001 - whatever a damaged one raises, it says nothing
        return {}
    return found if isinstance(found, dict) else {}


def _systemd_environment(text: str) -> dict[str, str]:
    """A service's Environment= lines as systemd reads them: indented or not, several assignments
    to a line, quoted or not, later ones winning, and an empty one clearing what came before.
    ValueError if one can't be read."""
    env: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("Environment="):
            continue
        value = line.removeprefix("Environment=")
        if not value:
            env.clear()
            continue
        for word in shlex.split(value):
            key, equals, setting = word.partition("=")
            if equals:
                env[key] = setting.replace("%%", "%")
    return env


def _timer_env(base: Path) -> dict[str, str] | None:
    """The environment the installed timer's run gets, as written. None if there's nothing to read;
    {} if there's something, and it can't be told or names nothing."""
    where = placement(sys.platform, (3, 0), {}, base, Path.home())
    for path in where.files:
        if path.suffix == ".plist" and path.exists():
            env = _plist(path).get("EnvironmentVariables")
            return {str(k): str(v) for k, v in env.items()} if isinstance(env, dict) else None
        if path.suffix == ".service" and path.exists():
            try:
                text = path.read_text(errors="replace")
            except OSError:
                return None
            if not text.strip():
                return None
            try:
                return _systemd_environment(text)
            except ValueError:
                return {}
    return None


def timer_of_another_home(base: Path) -> bool:
    """The timer's name is fixed, so it may run another copy of this tool: stopping or replacing it
    from here would stop that one's checks, and this one's servers aren't being checked by it. This
    tool always writes the home, so a timer with a body that doesn't name it isn't taken for ours.
    With nothing to read there's nothing to say it's another's, and nobody should be locked out."""
    env = _timer_env(base)
    if env is None:
        return False
    home = env.get("CHECKER_HOME")
    if not home:
        return True
    try:
        return Path(home).resolve() != base.resolve()
    except (OSError, ValueError):
        return True


def timer_environment_now(base: Path) -> dict[str, str]:
    """What a scheduled run will have that decides what it can reach: its agent's socket."""
    socket = (_timer_env(base) or {}).get("SSH_AUTH_SOCK")
    return {"SSH_AUTH_SOCK": socket} if socket else {}


def timer_running() -> bool | None:
    """Whether the timer is switched on (None: can't tell here). Files alone don't say: enabling
    it can fail, and someone can switch it off."""
    command = (
        ["launchctl", "print", f"gui/{os.getuid()}/{LAUNCHD_LABEL}"]
        if sys.platform == "darwin"
        else ["systemctl", "--user", "is-active", f"{UNIT}.timer"]
    )
    try:
        done = subprocess.run(  # noqa: S603
            command, capture_output=True, text=True, check=False, timeout=10
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if sys.platform == "darwin":
        if done.returncode == 0:
            return True
        return False if done.returncode in _NOT_LOADED else None
    state = done.stdout.strip()
    if state in ("active", "activating"):
        return True
    return False if state in ("inactive", "failed", "deactivating") else None


def forget_hosts(base: Path, hosts: list[str], identity, recipients: list[str]) -> None:
    """What the last run remembered of hosts whose evidence is all gone: it's derived from that
    evidence, and it would hide their next run's findings as not new. Alerts not yet delivered stay:
    deleting evidence mustn't also delete the news nobody has had."""
    if not hosts or not (base / STATE_FILE).exists():
        return
    state = load_state(base, identity)
    seen = state.get("hosts")
    if not isinstance(seen, dict) or not any(name in seen for name in hosts):
        return
    state["hosts"] = {name: value for name, value in seen.items() if name not in hosts}
    save_state(base, state, recipients)


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
