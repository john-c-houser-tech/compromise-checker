"""The demo fleet's story (plans/demo-story-2026-11-10.md): who the servers are, what happens on
each on which day, and what the person running the checker does about it.

It is data: demo.py plays it. In one sitting the days are minutes apart, each ending with a check
of every server; D.4 plays the same steps on their real days.

Where a real run showed the plan's story to be wrong, this is the story that holds (2026-11-10):

- `mail-1` is a Rocky server. A fresh Ubuntu 24.04 image is itself open to the brotli threat, so
  no Ubuntu server reads "No strong signs" on its first day.
- `db-1`'s routine work (a new account with full sudo, then a login as it) scores as a break-in
  would. The checker is right: nothing on the server tells the two apart. So the story keeps it,
  and the admin's acceptance is the point of the step.
- `shop-web-1` runs the older PHP too, so its break-in falls inside PHP2Shell's window.
"""

from __future__ import annotations

from dataclasses import dataclass

import detection_proof as detection
import php2shell_proof as php


@dataclass(frozen=True)
class Member:
    name: str
    group: str
    distro: str
    old_php: bool = False  # starts on the PHP that PHP2Shell is about


FLEET = (
    Member("shop-web-1", "web", "ubuntu24.04", old_php=True),
    Member("shop-web-2", "web", "ubuntu24.04", old_php=True),
    Member("db-1", "database", "rocky9"),
    Member("mail-1", "mail", "rocky9"),
    Member("app-1", "web", "rocky9"),
    Member("staging-1", "", "ubuntu24.04"),
)
UNREACHABLE = ("old-box", "192.0.2.10")  # a documentation address: nothing answers there
PHP = php.SCENARIOS["ubuntu-own"]

# The proofs' names for what they stage, as a demo should show them. The first table is for what
# a server is given before its first check (and the whitelist that explains it); the second for
# the break-in.
SETUP_NAMES = (
    ("proofuser", "webdev"),
    ("proofmail", "newsletter"),
    ("proofwebsecret", "tok-41c9e07a"),
    ("proofsitesecret", "key-9f2b6d13"),
    ("/var/www/proof", "/var/www/shop"),
    ("compromise-checker read-only proof: marker", "nightly maintenance: done"),
    ("cc-proof-web", "web-cache"),
    ("cc-proof-pod", "metrics"),
    ("proof.example", "shop.example"),
    ("PROOF_SECRET=not-for-the-checker", "API_TOKEN=not-for-the-checker"),
    ("export PROOF=1", "export EDITOR=vim"),
    ("proof.service", "sync.service"),
    ("/usr/bin/true proof", "/usr/bin/true sync"),
    ("echo proof", "echo sync"),
    ("Subject: proof\\n\\nproof\\n", "Subject: report\\n\\nnothing to report\\n"),
    ("compromise-checker proofs", "whoever set the server up"),
    ("The proof ", "Setting the server up "),
    ("- id: proof-", "- id: setup-"),
)
ATTACK_NAMES = (
    ("cc-toor", "sysmaint"),
    ("cc-proof-backdoor", "root@vps-4417"),
    ("cc proof", "System update"),
    ("cc-proof", "sysupdate"),
    ("ccadmin", "deploy2"),
    ("cc-sleep", "kworkerd"),
    ("cc-", "sys-"),
)


def renamed(text: str, names: tuple[tuple[str, str], ...]) -> str:
    for old, new in names:
        text = text.replace(old, new)
    return text


# --- what happens on the servers -----------------------------------------------------------

# Only the checker's server may log in, from before the first check: a server here is really
# weakened later, and stays up. {checker} is its address.
FIREWALL = r"""
set -eu
if command -v ufw >/dev/null 2>&1; then
    ufw allow from {checker} to any port 22 proto tcp >/dev/null
    ufw delete allow 22/tcp >/dev/null
    if ufw status | grep -Eq '^22/tcp +(\(v6\) +)?ALLOW +Anywhere'; then
        echo "ssh is still open to everyone" >&2; exit 1
    fi
else
    command -v firewall-cmd >/dev/null 2>&1 || dnf install -y -q firewalld >/dev/null
    systemctl enable --now firewalld >/dev/null 2>&1
    firewall-cmd -q --permanent \
        --add-rich-rule='rule family="ipv4" source address="{checker}" service name="ssh" accept'
    firewall-cmd -q --permanent --remove-service=ssh
    firewall-cmd -q --reload
    if firewall-cmd --list-services | grep -qw ssh; then
        echo "ssh is still open to everyone" >&2; exit 1
    fi
fi
"""

# Day 1, db-1: an admin's ordinary afternoon. A deploy account with full sudo, a nightly job, a
# package. The login as the new account follows (demo.py), as the admin trying it out.
ROUTINE_WORK = r"""
set -u
useradd -m -s /bin/bash deploy2
install -d -m 700 -o deploy2 -g deploy2 /home/deploy2/.ssh
echo '{admin_key} deploy2@laptop' > /home/deploy2/.ssh/authorized_keys
chown deploy2:deploy2 /home/deploy2/.ssh/authorized_keys
chmod 600 /home/deploy2/.ssh/authorized_keys
echo 'deploy2 ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/deploy2
chmod 440 /etc/sudoers.d/deploy2
echo '15 2 * * * root /usr/bin/true nightly-dump' > /etc/cron.d/nightly-dump
dnf install -y -q tmux >/dev/null 2>&1 || echo "STEP FAILED: package" >&2
"""

# Day 3, mail-1: a backup job is added. Day 4's rule explains it.
BACKUP_JOB = r"""
set -u
echo '30 1 * * * root /usr/bin/true mail-backup' > /etc/cron.d/mail-backup
"""

# Day 3, app-1: its firewall stops letting the checker in (someone tidied the rules). Done a
# moment after this returns, so the answer still gets back.
SHUT_OUT = r"""
set -u
rule='rule family="ipv4" source address="{checker}" service name="ssh" accept'
nohup sh -c "sleep 3; firewall-cmd -q --permanent --remove-rich-rule='$rule';
    firewall-cmd -q --reload" >/dev/null 2>&1 &
"""

# Day 4, shop-web-1: the intruder removes two of the things they left.
TIDY_UP = r"""
set -u
root=/usr/share/nginx/html
[ -d /etc/nginx/sites-enabled ] && root=/var/www/html
rm -f "$root/sys-shell.php" || echo "STEP FAILED: web shell" >&2
rm -f /etc/cron.d/sysupdate || echo "STEP FAILED: cron job" >&2
"""

# Day 4: the rule the admin writes for mail-1's backup job. {expires} is a date.
BACKUP_RULE = """\
  - id: mail-backup-job
    match: {{check: persistence.changes, path: /etc/cron.d/mail-backup}}
    reason: "The nightly mail backup, added by the mail team."
    owner: demo admin
    expires: {expires}
"""


# --- the story -----------------------------------------------------------------------------


@dataclass(frozen=True)
class Step:
    day: int
    where: str  # a server's name, or "admin"
    says: str  # what happens, in a line
    script: str = ""  # for root on the server, on standard input
    login: str = ""  # then a login as this account, with the planted admin key
    admin: tuple[str, ...] = ()  # or what the person running the checker does (demo.py's verbs)
    lost: bool = False  # the server can't be checked from here on


STORY = (
    Step(0, "admin", "sets the daily check", admin=("schedule", "03:00")),
    Step(
        1,
        "db-1",
        "an admin adds a deploy account with sudo, a nightly job and a package",
        script=ROUTINE_WORK,
        login="deploy2",
    ),  # fmt: skip
    Step(2, "shop-web-2", "PHP is updated; its service isn't restarted", script=PHP.fix),
    Step(
        2,
        "admin",
        "accepts db-1's changes as its baseline",
        admin=("accept", "db-1", "Routine work: the deploy account and nightly dump are ours."),
    ),  # fmt: skip
    Step(
        3,
        "shop-web-1",
        "the break-in",
        script=renamed(detection.ATTACKS, ATTACK_NAMES),
        login="deploy2",
    ),  # fmt: skip
    Step(3, "shop-web-2", "the PHP service is restarted", script=PHP.restart_fixed),
    Step(3, "mail-1", "a backup job is added", script=BACKUP_JOB),
    Step(3, "app-1", "its firewall stops letting the checker in", script=SHUT_OUT, lost=True),
    Step(4, "shop-web-1", "the intruder removes the web shell and the cron job", script=TIDY_UP),
    Step(4, "admin", "takes staging-1 off the list", admin=("remove", "staging-1")),
    Step(4, "admin", "writes a rule for mail-1's backup job", admin=("rule", "mail-1")),
    Step(
        5,
        "admin",
        "stops using one threat update by hand",
        admin=("retire", "dotnet-2026-10", "Nothing here runs .NET."),
    ),  # fmt: skip
)
# Each of these days ends with a check of every server. Day 5 doesn't: its point is the note that
# the threat updates have changed since the last result, which the next check would clear.
CHECKED_DAYS = (0, 1, 2, 3, 4)

# What only a person at the pages can produce (the story file's list), printed by `up` and
# `status`.
# The first is there because the Checks page lists only checks started from a page: the web
# service makes the entry itself and holds the running check, so no command can stand in for it,
# and the story's own checks (run by command, as the daily schedule runs them) aren't listed.
HANDS_ON = (
    "Checks: start one from the page. Until you do, the list is empty (see the story's notes).",
    "Known threats, Manage: put the stopped threat update back (the story's day 6).",
    "Start a check; start a second while it runs; stop one.",
    "Check app-1 alone (the firewall refuses it): the list of what to look at.",
    "Ask a server for its key again; paste a wrong fingerprint.",
    "Invite a view-only person, sign in as them in a private window.",
    "Settings: each field's refusals. The daily check's page.",
    "Delete stored evidence: one server's, and before a date.",
    "Add staging-1 back under its old name.",
    "Sign-in security: change password, recovery codes, wrong codes.",
    "Light, dark, and a phone's width, on each page.",
)
