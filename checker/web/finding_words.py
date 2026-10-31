"""Each check's finding in plain words: what it could mean and what to do. A finding's own
title and summary stay exact, and are shown beside these as the details. Careful words:
a finding is a reason to look, not proof, and many have innocent explanations."""

# check id: (what this is, what to do)
WORDS = {
    "files.scratch": (
        "A program or script is sitting in a temporary folder. Attackers often work from there, though some installers do too.",
        "Ask whoever runs this server if they put it there. If nobody did, treat it as a break-in.",
    ),
    "files.deceptive": (
        "A file's name looks chosen to hide it, or to pass for part of the system.",
        "Have someone look at the file before deleting anything: it may be evidence.",
    ),
    "files.dev": (
        "A file is in a system folder where ordinary files don't belong. It's a known hiding place.",
        "Have someone look at the file before deleting anything: it may be evidence.",
    ),
    "files.web": (
        "A script on your website is new or changed, or is in a folder meant for uploads. Attackers plant scripts like this to control a server through its website.",
        "Check whether it came from an update you know about. If not, treat it as a break-in.",
    ),
    "files.backdated": (
        "A program's date has been set back, which makes a new file look old. Very little legitimate software does this.",
        "Have someone look at the file before deleting anything: it may be evidence.",
    ),
    "web.worker_child": (
        "The program serving your website started a command line or a download tool. Websites rarely need to, and it's what a website break-in looks like.",
        "Treat this as urgent. Find out which site and which request caused it.",
    ),
    "web.new_script_hit": (
        "Someone visited a script that's new on your website. A planted script gets used this way.",
        "Check whether the script is yours. If not, treat it as a break-in.",
    ),
    "web.exploit": (
        "Web requests contained known attack patterns. Most websites get these all the time; it matters more if your site answered them.",
        "Make sure the website and its software are up to date.",
    ),
    "web.errors": (
        "One address caused a burst of errors on your website. It may be someone probing for a weakness.",
        "Look at what the requests were after, and keep the website's software up to date.",
    ),
    "web.noise": (
        "Automated scanners asked for pages your site doesn't have. Every website on the internet gets this.",
        "Nothing, unless other findings point the same way.",
    ),
    "account.uid0": (
        "An account has the same total control as the administrator, under another name. This is a classic back door.",
        "Treat this as urgent. Unless someone you trust set it up on purpose, treat it as a break-in.",
    ),
    "account.changes": (
        "User accounts have been added, removed or given new abilities.",
        "Check that someone you know made these changes, and why.",
    ),
    "account.log_changes": (
        "The logs show accounts or groups being changed.",
        "Check that someone you know made these changes, and why.",
    ),
    "sudo.rules": (
        "An account was given new administrator rights. Attackers do this to keep control.",
        "Check that someone you know gave these rights, and why.",
    ),
    "group.privileged": (
        "An account joined a group that gives it administrator-level control.",
        "Check that someone you know added it, and why.",
    ),
    "ssh.authorized_keys": (
        "A login key was added or changed. A key lets someone log in without a password, so attackers often leave one behind.",
        "Check that each key belongs to someone you know. Remove any that doesn't, after keeping a copy as evidence.",
    ),
    "ssh.guessed": (
        "Someone failed to log in and then succeeded from the same address. That can mean a password was guessed.",
        "Ask the account's owner if it was them. If not, change the password and treat it as a break-in.",
    ),
    "ssh.login": (
        "Someone logged in directly as the administrator, or from an address not seen before.",
        "Ask whoever uses this account if it was them.",
    ),
    "ssh.login_hours": (
        "An account logged in at an unusual time for it.",
        "Ask whoever uses this account if it was them.",
    ),
    "account.password": (
        "Passwords were changed, or someone switched accounts or was refused administrator rights.",
        "Check that these were people you know doing their work.",
    ),
    "sshd.config": (
        "The settings for logging in to this server remotely have changed.",
        "Check that someone you know changed them, and why.",
    ),
    "pam.changes": (
        "The part of the system that checks passwords has changed. Attackers change it to steal passwords or let themselves in.",
        "Unless an update you know about explains it, treat this as serious.",
    ),
    "logs.cleared": (
        "Logs were cleared or replaced. Log rotation can look similar, but people cover their tracks this way.",
        "Find out who did this and why. Keep any copies of the logs you have.",
    ),
    "logs.stopped": (
        "Logging was stopped or turned down, so the server records less about what happens on it.",
        "Find out who did this and why, and turn it back on.",
    ),
    "logs.journald_config": (
        "The system's log was set to keep little or nothing.",
        "Find out who did this and why, and restore the setting.",
    ),
    "history.disabled": (
        "The record of typed commands was turned off or emptied. People cover their tracks this way.",
        "Find out who did this and why.",
    ),
    "mac.disabled": (
        "A built-in protection (SELinux or AppArmor) was turned down.",
        "Find out who did this and why, and turn it back on.",
    ),
    "agent.stopped": (
        "Security software that was running before isn't running now.",
        "Find out why, and start it again.",
    ),
    "clock.jump": (
        "The system clock was set by hand. This can make logs misleading.",
        "Find out who did this and why.",
    ),
    "container.privileged": (
        "A container has enough access to take over the whole server.",
        "Check that it needs this access. Many don't.",
    ),
    "container.host_namespace": (
        "A container is sharing parts of the server that containers normally keep apart.",
        "Check that someone you know set this up, and why.",
    ),
    "container.new": (
        "A new container is running, or an existing one is running different software.",
        "Check that someone you know started it.",
    ),
    "package.changed": (
        "A system file is different from the one its software package installed. Attackers alter system programs to hide themselves.",
        "Have someone compare it with a fresh copy. Settings files often differ innocently; programs shouldn't.",
    ),
    "files.privileged": (
        "A program can run with administrator power whoever starts it. It's a way back in if an attacker left it.",
        "Check that it belongs to software you know.",
    ),
    "files.unowned": (
        "A program is in a system folder, but no installed software put it there.",
        "Find out where it came from.",
    ),
    "kernel.oom_kill": (
        "The server ran out of memory and stopped a program. It's usually a capacity problem, though unwanted software can cause it.",
        "Check what used the memory.",
    ),
    "kernel.segfault": (
        "A program crashed. Repeated crashes in something facing the internet can mean someone is attacking it.",
        "Keep that software up to date, and look into repeated crashes.",
    ),
    "kernel.errors": (
        "The core of the system reported errors. This is usually hardware or a bug.",
        "Have someone look if it repeats.",
    ),
    "kernel.taint": (
        "The core of the system loaded a module from outside the usual software. Some drivers do this, and so do the most serious kinds of attack.",
        "Find out which module it is and where it came from.",
    ),
    "kernel.core_dump": (
        "A program facing the internet crashed. Someone attacking it can cause this.",
        "Keep that software up to date, and look into repeated crashes.",
    ),
    "mail.web_user": (
        "Your website's account sent email. Attackers use broken-into websites to send spam.",
        "Check whether your site sends mail itself, such as contact forms.",
    ),
    "mail.relay": (
        "The server's mail settings changed, or it may send mail for anyone. Spammers look for this.",
        "Check that someone you know changed them.",
    ),
    "mail.volume": (
        "This server suddenly sent much more mail than usual. That can mean it's sending spam.",
        "Check what was sent and by which account.",
    ),
    "mail.domains": (
        "This server wrote to many new places in one day, which looks like spam.",
        "Check what was sent and by which account.",
    ),
    "process.hidden": (
        "A running program is hidden from the system's own list. Very little legitimate software does this.",
        "Treat this as urgent, and have someone investigate before restarting the server.",
    ),
    "process.executable": (
        "A running program has no file behind it, or runs from a temporary place, or is posing as part of the system.",
        "Treat this as serious. Don't restart the server until someone has looked, since that loses evidence.",
    ),
    "process.reverse_shell": (
        "A command line on this server is connected out over the network. It's how an attacker controls a server remotely.",
        "Treat this as urgent, and have someone investigate before restarting the server.",
    ),
    "process.miner": (
        "A program looks like cryptocurrency mining, which is a common use for broken-into servers.",
        "Treat this as a break-in, since a miner got in somehow.",
    ),
    "process.injected": (
        "A running program has code loaded from somewhere unusual. Attackers do this to hide inside normal programs, though some software does it innocently.",
        "Have someone look at which program and which code.",
    ),
    "net.listener": (
        "A program started accepting connections from the network. That may be a new service or a back door.",
        "Check that you know what it is.",
    ),
    "net.peer": (
        "This server connected somewhere new, or to the anonymous Tor network.",
        "Check that you know what's connecting and why.",
    ),
    "net.metadata": (
        "A program asked your cloud provider for this server's settings, which can include keys.",
        "Check which program it was. If unexpected, change any keys the server holds.",
    ),
    "net.directory": (
        "Your website's account contacted a company directory service, which websites rarely do. It's how an attacker moves further in.",
        "Treat this as urgent if your site doesn't use one.",
    ),
    "net.tunnel": (
        "A remote connection is carrying other traffic through this server, which can get around a firewall.",
        "Check that someone you know set it up.",
    ),
    "net.config": (
        "Network or firewall settings changed.",
        "Check that someone you know changed them.",
    ),
    "net.firewall_comment": (
        "A firewall rule may be disguised by its comment, so it may not do what it appears to.",
        "Have someone read the firewall rules directly.",
    ),
    "net.managed_chain": (
        "Firewall rules are named after a program that isn't running, which can be a way of hiding them.",
        "Have someone read the firewall rules directly.",
    ),
    "net.promiscuous": (
        "A network connection is capturing all traffic. Diagnostic tools do this, and so does someone stealing data.",
        "Find out which program is doing it.",
    ),
    "net.transfer": (
        "There are weak signs of data leaving this server: large archives or transfer tools.",
        "Check that these are your own backups or transfers.",
    ),
    "pack.detection": (
        "A sign of a known attack was found while this server was open to it.",
        "Treat this as serious, and follow the advice about this threat.",
    ),
    "pack.exposure": (
        "This server has been affected by a known, active threat.",
        "Update this server's software, then restart its services.",
    ),
    "persistence.ld_preload": (
        "Something is set to load into every program on this server. Attackers use this to hide and to steal passwords.",
        "Treat this as serious unless someone you know set it up.",
    ),
    "persistence.changes": (
        "Something new is set to run automatically. Attackers use this to stay on a server after a restart, and normal software does it too.",
        "Check that you know what it is.",
    ),
    "persistence.at_jobs": (
        "A command is queued to run later.",
        "Check that you know what it is.",
    ),
    "persistence.homes": (
        "A user's account has something set to start by itself.",
        "Check that it belongs to something you know.",
    ),
    "system.reboot": (
        "This server restarted. Usually that's routine, but an unexplained restart is worth a question.",
        "Check that you know why it restarted.",
    ),
    "software.packages": (
        "Software was installed, removed or upgraded. Usually that's routine maintenance.",
        "Check that it fits work you know about.",
    ),
    "software.repository": (
        "A new place to get software from was added, or a signing key changed. That can be used to install something unwanted.",
        "Check that someone you know added it.",
    ),
    "software.tools": (
        "Attack tools or a compiler were installed. Servers rarely need them.",
        "Find out who installed them and why.",
    ),
    "software.global": (
        "Software was installed by hand, outside the normal way.",
        "Check that someone you know installed it.",
    ),
}
# Where one kind of finding from a check means something different.
BY_VARIANT = {
    ("account.changes", "new"): (
        "A new user account appeared on this server. Attackers add accounts so they can come back.",
        "Check that someone you know made it, and why.",
    ),
    ("account.changes", "removed"): (
        "A user account was removed.",
        "Check that someone you know removed it, and why.",
    ),
    ("account.changes", "root_group"): (
        "A new account has been given administrator-level control through its group.",
        "Check that someone you know made it, and why. If not, treat it as a break-in.",
    ),
    ("account.changes", "service_login"): (
        "An account meant only for running software can now be logged in to, which attackers look for.",
        "Check that someone you know changed it, and why.",
    ),
    ("pack.exposure", "vulnerable"): (
        "This server is running a version with a known flaw that attackers are using now.",
        "Update this server's software, then restart its services.",
    ),
    ("pack.exposure", "cant_judge"): (
        "This server may have a known flaw that attackers are using, but the check can't tell from the version it runs.",
        "Ask whoever runs this server whether this version has the fix.",
    ),
    ("pack.exposure", "was_exposed"): (
        "This server had a known flaw while attackers were using it. It's fixed now, but someone could have got in before that.",
        "Look through this page for signs of a break-in from that time.",
    ),
    ("pack.exposure", "stale_code"): (
        "The fix is installed, but a program is still running the old code.",
        "Restart its services.",
    ),
    ("pack.exposure", "mitigation_missing"): (
        "A setting that reduces the risk from a known threat isn't in place.",
        "Follow the advice about this threat.",
    ),
    ("web.exploit", "answered"): (
        "Your site answered a web request containing a known attack pattern, so the attack may have reached it.",
        "Check that the site's software is up to date, and look at what the request did.",
    ),
    ("web.exploit", "refused"): (
        "Web requests contained known attack patterns, and your site refused them. Every website gets these.",
        "Keep the website's software up to date.",
    ),
    ("system.reboot", "unclean"): (
        "This server stopped without shutting down properly. A power cut or a crash can do that, and so can someone forcing a restart.",
        "Check that you know why it happened.",
    ),
}
# What a check couldn't see, by how the tool says it. Anything else is shown as it is.
GAP_WORDS = (
    ("no authentication log events", "Any record of logins, so it can't tell who has logged in."),
    (
        "no system journal events",
        "The system's own log, so it can't see shutdowns or system errors.",
    ),
    ("no boot list", "Any record of restarts, so it can't tell why this server restarted."),
    ("the host's clock is", "The right time: this server's clock is off, so times may be wrong."),
    ("the host's time zone", "This server's time zone, so times in some logs may be off by hours."),
    ("the bundle is", "All of this server: the last check only saw part of it."),
    ("mail logs not collected", "Its outgoing mail, since mail logs weren't collected."),
)
FALLBACK = ("The check noticed something worth a look.", "Ask whoever runs this server about it.")
BAND_WORDS = {
    "critical": "Very serious",
    "high": "Serious",
    "medium": "Worth a look",
    "low": "Minor",
    "info": "For information",
}
SECTIONS = {
    "compromise indicator": "Signs of a break-in",
    "exposure": "Known threats",
    "hygiene": "Weak spots that make a break-in easier",
}


def words_for(check: object, variant: object) -> tuple[str, str]:
    try:
        return BY_VARIANT.get((check, variant)) or WORDS.get(check) or FALLBACK
    except TypeError:  # an odd stored value isn't hashable
        return FALLBACK


def gap_words(gap: object) -> str:
    text = gap if isinstance(gap, str) else str(gap)
    for start, words in GAP_WORDS:
        if text.startswith(start):
            return words
    return text
