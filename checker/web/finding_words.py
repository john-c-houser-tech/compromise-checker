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
        "A program or script has a date much older than when it was written to disk. Unpacking an archive or installing software does this, and attackers also do it to make a new file look old.",
        "Check whether it came from software you installed. If not, have someone look before deleting anything.",
    ),
    "web.worker_child": (
        "The program serving your website started a command line or a download tool. Websites rarely need to, and it's what a website break-in looks like.",
        "Treat this as urgent unless your site is known to run this. Find out which site and which request caused it.",
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
        "An account joined a group that gives it administrator-level control, or lets it read all the logs.",
        "Check that someone you know added it, and why.",
    ),
    "ssh.authorized_keys": (
        "A login key was added or changed. A key lets someone log in without a password, so attackers often leave one behind.",
        "Check that each key belongs to someone you know. If one isn't recognised, treat it as a break-in and get advice before removing it.",
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
        "The part of the system that checks passwords has been changed, or runs something unusual. Attackers do this to steal passwords or let themselves in.",
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
        "The system clock was changed. Time-sync software does this; someone doing it by hand can make logs misleading.",
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
        "If nobody here runs one on purpose, treat it as a break-in. Don't stop it or restart until someone has looked.",
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
        "Your website's account contacted a company directory service. Some sites log users in this way; if yours doesn't, it can be how an attacker moves further in.",
        "Find out whether your site uses one. If it doesn't, treat this as urgent.",
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
        "Treat this as serious, and have someone investigate before changing anything.",
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
    ("process.injected", "replaced"): (
        "A running program is still using a file that an update has since replaced. This is normal after updates, but it keeps running the old code.",
        "Restart it when convenient, unless this page shows signs of a break-in. If it does, get advice first.",
    ),
    ("kernel.taint", "unexplained"): (
        "The core of the system shows a module was loaded, but none is listed. A module may be hiding itself, which is one of the most serious kinds of attack.",
        "Treat this as urgent, and have someone investigate before restarting: a restart loses the evidence.",
    ),
    ("logs.stopped", "moved"): (
        "This logging program is now running from a different file than before. It may be an impostor.",
        "Treat this as serious, and have someone check that file before changing anything.",
    ),
    ("agent.stopped", "moved"): (
        "This security program is now running from a different file than before. It may be an impostor.",
        "Treat this as serious, and have someone check that file before changing anything.",
    ),
    ("container.privileged", "new"): (
        "A new container has enough access to take over the whole server.",
        "Check that someone you know started it. If not, treat it as a break-in.",
    ),
    ("software.tools", "compiler"): (
        "A compiler was installed. Developers use these, and so do attackers building tools on a server.",
        "Find out who installed it and why.",
    ),
    ("ssh.authorized_keys", "unattributed"): (
        "A login key sits in a place that belongs to no account on this server.",
        "Find out whose it is. If nobody knows, treat it as a break-in and get advice before removing it.",
    ),
    ("mail.relay", "open_relay"): (
        "This server may send mail for anyone, which spammers look for.",
        "Have someone close this.",
    ),
    ("mail.volume", "queue"): (
        "Many messages are waiting to go out. A mail problem can cause this, and so can spam.",
        "Check what's waiting and which account sent it.",
    ),
    ("net.config", "json_lost"): (
        "The firewall rules can no longer be read in the reliable form, so a disguised rule could go unnoticed.",
        "Have someone read the firewall rules directly.",
    ),
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
        "Update this server's software, then restart its services. If no fix exists yet, have someone apply a workaround. If this page also shows signs of a break-in, get advice first, since restarting loses evidence.",
    ),
    ("pack.exposure", "cant_judge"): (
        "This server may have a known flaw that attackers are using, but the check can't tell from the version it runs.",
        "Ask whoever runs this server whether this version has the fix. If the check saw only part of the package list, run a fresh check.",
    ),
    ("pack.exposure", "was_exposed"): (
        "This server may have had a known flaw while attackers were using it. The flawed version isn't installed now, but someone could have got in then.",
        "Look through this page for signs of a break-in.",
    ),
    ("pack.exposure", "stale_code"): (
        "The fix is installed, but a program is still running the old code.",
        "Restart its services. If this page also shows signs of a break-in, get advice first, since restarting loses evidence.",
    ),
    ("pack.exposure", "mitigation_missing"): (
        "A setting that reduces the risk from a known threat isn't in place.",
        "Have someone make the setting named here.",
    ),
    ("web.exploit", "answered"): (
        "Your site answered a web request containing a known attack pattern, so the attack may have reached it.",
        "Check that the site's software is up to date, and look at what the request did.",
    ),
    ("web.exploit", "refused"): (
        "Web requests contained known attack patterns, and the check judged they did no harm. Every website gets these.",
        "Keep the website's software up to date.",
    ),
    ("system.reboot", "unclean"): (
        "This server stopped without shutting down properly. A power cut or a crash can do that, and so can someone forcing a restart.",
        "Check that you know why it happened.",
    ),
}
# Where a check's kinds of finding have no variant to tell them apart, by the finding's own
# title. Only for titles the tool writes; a test checks each is still in the checks' source.
BY_TITLE = (
    (
        "process.executable",
        "A process still running a replaced program",
        (
            "A running program is still using a version that an update has since replaced. This is normal after updates, but it keeps running the old code.",
            "Restart it when convenient, unless this page shows signs of a break-in. If it does, get advice first.",
        ),
    ),
    (
        "package.changed",
        "The package managers' checksum lists changed",
        (
            "The package manager's records of its files changed. Installs and updates do this.",
            "Check that it fits updates you know about.",
        ),
    ),
    (
        "account.uid0",
        "Accounts sharing a UID",
        (
            "Two accounts share one identity number, so the system can't tell them apart.",
            "Find out who set this up, and why.",
        ),
    ),
    (
        "account.uid0",
        "An account name listed twice",
        (
            "The same account name is listed twice, which can confuse the system about who's who.",
            "Find out who set this up, and why.",
        ),
    ),
    (
        "files.web",
        "A secrets or repository file",
        (
            "A file holding secrets or your site's source code is in a website folder, so anyone may be able to download it.",
            "Have someone move or block it, and change any passwords in it.",
        ),
    ),
    (
        "files.web",
        "A link out of the web root",
        (
            "A link in your website's folder leads outside it, which can expose other files on the server.",
            "Check that someone you know set it up.",
        ),
    ),
    (
        "files.web",
        "A program in a web root",
        (
            "A program is in your website's folder, where only web pages and scripts normally belong.",
            "Check whether it came from an update you know about. If not, treat it as a break-in.",
        ),
    ),
    (
        "files.dev",
        "A device node outside /dev",
        (
            "A special device file is outside the place they belong. It can give direct access to memory or disks.",
            "Have someone look at the file before deleting anything: it may be evidence.",
        ),
    ),
    (
        "kernel.core_dump",
        "A new crash dump file",
        (
            "A program crashed and left a dump file.",
            "Have someone look if it repeats.",
        ),
    ),
    (
        "kernel.taint",
        "The kernel became tainted",
        (
            "The core of the system reported a problem or a warning, or loaded something from outside the usual software.",
            "Have someone look at what it reported.",
        ),
    ),
    (
        "persistence.ld_preload",
        "A process runs with LD_PRELOAD",
        (
            "One running program was started with extra code loaded into it. Attackers use this to hide and to steal passwords, though some software does it innocently.",
            "Find out which program it is and what's being loaded.",
        ),
    ),
)
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
    "exposure": "Known threats and exposed settings",
    "hygiene": "Weak spots and system problems",
}


def words_for(check: object, variant: object, title: object = None) -> tuple[str, str]:
    try:
        if found := BY_VARIANT.get((check, variant)):
            return found
        if isinstance(title, str):
            for on, start, words in BY_TITLE:
                if on == check and title.startswith(start):
                    return words
        return WORDS.get(check) or FALLBACK
    except TypeError:  # an odd stored value isn't hashable
        return FALLBACK


def gap_words(gap: object) -> str:
    text = gap if isinstance(gap, str) else str(gap)
    for start, words in GAP_WORDS:
        if text.startswith(start):
            return words
    return text
