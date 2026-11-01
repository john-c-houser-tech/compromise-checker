# Security and Privacy Policy

**Compromise Checker** (working title), published by NouriLoop LLC.
Version 0.1 (draft), 2026-10-29.

This policy describes how the software behaves from its first release. Builds
made before that release may not do everything described here yet; the
README's *Status* section says what is built so far.

---

## 1. Who this is for

This policy is for the people who decide whether the tool may be used in an
organization: system administrators, security teams, privacy officers and
legal reviewers.

Compromise Checker is software you run yourself. It logs into Linux servers
you name, collects evidence of possible compromise without changing anything,
and analyses that evidence on a machine you control. **NouriLoop LLC does not
run a service, does not receive your data, and cannot see anything the tool
collects.**

## 2. The short version

- The tool only reads. It never changes, deletes or installs anything on the
  servers it checks, and it writes nothing to their disks.
- It leaves the ordinary traces any administrator's login leaves (login and
  sudo records), and it never hides or removes them.
- Evidence is encrypted with a key your organization holds, kept 90 days by
  default, and can be deleted at any time.
- Likely secrets are masked before evidence leaves a server.
- Nothing leaves your organization unless you turn on the optional AI
  advisor, and then only what section 9 describes, sent with your own
  account to the AI provider you choose.
- No telemetry. The tool never contacts NouriLoop LLC.

## 3. Authorization and accountability

- Use the tool only on systems you are authorized to assess.
- The tool checks only the servers listed in its inventory. It has no mode
  that searches networks for servers.
- Every run is recorded with the operator, the machine it ran from, the time,
  and the servers checked.

## 4. What the tool does on a server

- It opens an SSH session and runs the server's own Python interpreter. The
  collector program is sent over the session's input and its results return
  over the session's output. **No file is created on the server.**
- The collector reads log files, system configuration, package records and
  the kernel's process information under `/proc`. Where a file cannot
  practically be read directly, it runs a command from a short published
  list of read-only commands (for example `journalctl` for the systemd
  journal, and the package manager's verify command). Each command used is
  recorded with the evidence.
- It never writes, renames, deletes or changes the permissions of anything.
- It runs at the lowest CPU and disk priority, with a time limit and size
  limits, so that it does not disturb the server's normal work.
- The collector is a single, human-readable file published with the
  software. A fingerprint (SHA-256 hash) of the exact collector that ran is
  stored with every collection, so you can always check what ran.

## 5. Traces the tool leaves, and why it never removes them

Any login leaves records. The tool's runs leave these:

- the SSH login, in the server's authentication log and login records
  (`wtmp`, `lastlog` or `wtmpdb`);
- the `sudo` entry in the authentication log, plus sudo's own short-lived
  timestamp record (held in memory under `/run`) and, the first time an
  account uses sudo, sudo's one-time notice marker;
- records of the commands run, if the server's audit system is configured to
  keep them;
- on a server whose `sudo` takes rules from a directory service (such as
  SSSD or LDAP), the tool's look-up of the scanner account's own `sudo`
  rules: the directory service may refresh its cache of those rules as it
  answers, and if `sudo` can't reach it, `sudo` may mail the administrators
  about it (for the tool's own `sudo` as well as the look-up);
- the system's ordinary session setup for the account: a per-login runtime
  area in memory (`/run/user/…`) and, on Ubuntu, its login-message files,
  including one small marker file (`.cache/motd.legal-displayed`) in the
  scanner account's home directory on its first login; where Ubuntu's
  Landscape client is installed, the login message's system summary also
  refreshes its cache and log file (under `/var/lib/landscape` and
  `/var/log/landscape`); on Red Hat Enterprise Linux 9 and later, and its
  rebuilds, a login session that lasts a few minutes also has the system
  record that the last boot succeeded (`/boot/grub2/grubenv`).

**The tool never removes, edits or suppresses any of these.** On a server
that may be compromised, changing logs destroys evidence, and it is exactly
what an attacker does. Instead, the tool recognises its own sessions (by
time, source address and key fingerprint) and leaves them out of its
findings.

## 6. Credentials

- SSH keys are used through an SSH agent, or from a key file you name. The tool
  never stores keys or passwords in readable form.
- Passwords come from a prompt, a page of the web interface, the operating
  system's keyring, or your secrets manager. They are kept in memory only for the run, never written to
  logs, and never placed on a command line, where other users and audit logs
  could see them. A sudo password travels inside the encrypted SSH session.
- Every server's identity is checked on every connection. Someone has to
  accept a server's key the first time: on the command line by comparing the
  fingerprint it shows, and in the web interface by pasting the fingerprint from
  the server itself, which the tool compares with what the server offers. A
  changed key stops the run. This check cannot be switched off.
- The recommended setup is a dedicated scanner account that can log in only
  with a key, and whose sudo permission is limited to running the Python
  interpreter. That permission is equivalent to full administrator access.
  It is acceptable here because the program run is published, fixed, and
  fingerprinted with every collection, but your security team should know it
  and decide.

## 7. What is collected

Evidence from a server contains personal and sensitive information:
usernames, IP addresses, the domains of email addresses in mail logs (the
rest of each address is replaced by a fingerprint, see below), web addresses
that may include access tokens, and sometimes secrets typed into commands.

- **Only what the checks need.** Each part of the collector documents what it
  reads and why. The time window collected is limited (30 days by default).
- **Web server logs.** Web server *error* logs (nginx, Apache, PHP-FPM) are
  always collected, because attacks on web applications usually show there
  first. Full *access* logs, which record every visitor's request, are
  collected only if your organization chooses this during setup. In both,
  visitors' IP addresses are kept, since they are what an investigation
  follows. The values in web addresses' query strings and in referrers are
  replaced by a marker, with their names kept, except that a value matching
  a known attack pattern is replaced by a marker naming that pattern. User
  agents are cut to 256 characters, and secret masking always applies.
- **Programs started by web server accounts.** Where the server's audit
  system records program starts, those started by the web server's accounts
  (`www-data`, `apache`, `nginx`, and any your organization names) are
  collected, with their arguments masked like other command lines, because a
  web server starting a shell is one of the clearest signs of a break-in.
  Your organization can choose during setup to collect program starts for
  root, service accounts and accounts with administrator rights too, and,
  only with that, for ordinary users.
- **Package history and PHP settings.** The record of package installs,
  upgrades and removals (from dpkg's log or dnf's history, up to about a
  year back; package names, versions and times only) and the settings in
  PHP's configuration files (setting names and values, masked; comments
  left out), so a threat pack can tell when a fix arrived and whether a
  recommended setting is in place.
- **Sites' own PHP settings.** In the web folders the tool already examines,
  the PHP setting lines of `.user.ini` and `.htaccess` files (setting names
  and values, masked; nothing else from those files), because a site can
  override a protective PHP setting there.
- **Mail logs.** Outgoing mail logs (Postfix, Exim) are collected, because
  mail sent from a compromised server is a common sign of misuse. Before they
  leave the server, every email address in them is changed: the part before
  the @ is replaced by a keyed fingerprint, made with a key your organization
  holds (created at setup), and the domain is kept. The same address always
  gives the same fingerprint, so volumes and new recipients can be counted
  without any address being shown. Someone who holds the key can check
  whether a given address appears (`checker mail-hash`); without it, the
  fingerprints can't be turned back into addresses. The key is sent to a
  server only for a collection, held in memory and never written there: it
  isn't sent before a first collection has shown that the server's `sudo`
  doesn't record its input, nor to a server whose `sudo` did so at its last
  collection; such a server's mail logs aren't collected.
  Message subjects and contents aren't in these logs and are never collected.
- **Shell history.** Information *about* history files (whether they exist,
  their size and dates, and whether history has been switched off) is always
  collected, because switching history off is a common way of covering
  tracks. The *commands themselves* are collected only if your organization
  chooses this during setup, and then only for root, service accounts and
  accounts with administrator rights unless you also enable it for ordinary
  users.
- **Containers.** Where Docker or Podman runs, what each container is
  allowed to do is read from the runtimes' own state files, never by
  connecting to them: its name and image, whether it is privileged, its
  capabilities and devices, whether it shares the host's processes or
  network, and which host folders it mounts. A container's environment and
  labels, which often hold passwords and keys, are never collected.
- **Scheduled jobs and start-up files.** Crontabs and queued `at` jobs are
  collected as masked text, but each `at` job's stored copy of the
  submitting user's environment is left out; only the variable names are
  kept. Start-up files and systemd units in home directories are collected
  as metadata and a SHA-256 fingerprint only, unless your organization
  chooses during setup to collect their text too; then only for root,
  service accounts and accounts with administrator rights, unless you also
  enable it for ordinary users. Secret masking always applies.
- **Secret masking.** Before evidence leaves the server, the collector
  replaces text matching these patterns with a marker such as
  `[MASKED:password]`:
  - private key blocks (`-----BEGIN … PRIVATE KEY-----` to the matching end,
    for as long as the lines look like key material, so a fake start line
    cannot hide the lines after it);
  - values of settings and command options named like password, passwd, pwd,
    secret, token, api key, access key or auth (including `-p<password>` for
    MySQL clients);
  - HTTP `Authorization` headers and bearer tokens;
  - passwords inside web addresses (`scheme://user:password@host`);
  - password hashes in the standard crypt formats (`$1$`, `$2b$`, `$5$`,
    `$6$`, `$y$` and similar);
  - user names in failed-login records and messages that don't match a
    local account (a password is sometimes typed into the user-name box by
    mistake);
  - passwords given to command-line options that take one without saying
    so (for example `sshpass -p`, `redis-cli -a`, `curl -u user:password`,
    `docker login -p`, openssl's `pass:` and `htpasswd -b`), and values
    after key names such as `aws_secret_access_key`;
  - well-known credential formats, including cloud access keys, GitHub,
    Slack, Stripe and Anthropic API keys, and signed web tokens (JWTs).

  Masking is pattern-based and cannot catch every secret. Treat collected
  evidence as sensitive even after masking. Reports state that masking ran
  and which rule version was used.

## 8. How evidence is stored

- **Encrypted.** Each collection is encrypted as it arrives, using the `age`
  encryption format, to a key created for your organization at setup. Keep
  that key's backup safe: without it, stored evidence cannot be read.
- **Index.** An index records each collection's identifiers, times, status,
  size and fingerprints — never its content.
- **Tamper-evident.** Each collection carries fingerprints (SHA-256) of its
  contents and of the encrypted file, and a chain-of-custody record of who
  collected it, when, from which machine and from which server. Stored
  collections are never modified.
- **Retention.** Evidence, snapshots and reports are kept for 90 days by
  default. You can change the period. A `purge` command or a page of the
  web interface deletes everything stored for a server or a date range, and can
  delete whatever is past its retention period, which a daily check also does. An
  alert not yet delivered stays until it is; the tool reminds
  you when anything is due. One exception: a server's current baseline, the
  collection later checks compare against, is kept until a newer one is
  accepted, because deleting it would hide changes made since. Data for a
  server removed from the inventory has no such exception. Each purge is
  recorded by identifiers, times and counts only, never content.
- **Reports are confidential documents.** They describe weaknesses an attacker
  could use, so they are encrypted to the same key as the evidence. Showing
  one (`checker report --open`) serves it to your browser from memory, on
  this machine only, without writing a plain copy. A report written as plain
  HTML on purpose (`--plain`), to hand on, is yours to protect: handle it
  like the evidence.
- **The web interface.** If you run it, it decrypts evidence in memory for each
  page, using the same key as the command line, and tells browsers not to keep
  the pages. So the web server can read everything the tool has stored, and
  anyone with an account can see every result: treat an account like access to
  the evidence itself. It keeps accounts with hashed passwords, sessions, and
  failed logins for 15 minutes (with their usernames and addresses) in its own
  owner-only file, and never evidence. By default only this machine can reach
  it, and it won't listen more widely without TLS.
  An account can also add and change servers, after confirming with its
  password, and a code if two-factor sign-in is on. That includes naming any key
  file the web server can read and which Python runs as administrator on a
  server. So someone with an account could use those keys to log in elsewhere,
  or send the next typed password to a machine they control. The same
  confirmation lets an account change what is collected and how long evidence is
  kept, delete stored evidence, set or stop a daily check, turn the AI advisor on, choose how much is hidden from it, and stop threat
  packs or keep them off a server. Asking for the latest signed packs needs no
  confirmation. Apart from the daily check, which
  runs the tool's own fixed command and any notify command already set, anything
  that runs a command on this machine, or sends data or keys to another address,
  can only be changed on the command line. Each such
  change is recorded, but the record doesn't prevent it. Give accounts only to
  people you would trust with the servers themselves.
  If you start a check from its pages, the web server starts the same run the
  command line does, connecting to your servers with the same settings. What
  that check reports is held in memory, not on disk, and holds no findings. A
  restart of the web server stops it. A daily check set from a page is different:
  it connects to your servers with nobody there, and keeps running when the web
  server is stopped, until someone stops it.
- **The activity record.** The web interface keeps a permanent record of who
  signed in and out, who viewed which server's results and evidence, and each
  action taken from its pages, with the time and the address it came from. It
  holds no evidence, and failed logins aren't in it. It can't be changed from
  the pages, but anyone with full control of the machine could alter it. It
  isn't removed by `purge` or by the retention period: to remove it, delete the
  web interface's file. If the record can't be written, for example on a full
  disk, viewing results and evidence still works, and those events go to the
  tool's error output instead; actions are refused. Signing out then clears
  only that browser: the session can stay valid on the server until it expires,
  up to 8 hours, and the page says so.
- **Two-factor sign-in.** The web interface's file also holds each account's
  authenticator secret and its unused recovery codes, in readable form, since
  the tool has to check codes against them. The file is readable only by the
  tool's owner, but a copy of it, or a backup, should be protected like a
  password. They aren't sent anywhere.

## 9. The optional AI advisor

The tool can use an AI model to explain an analysis, propose whitelist rules
for a person to review, suggest settings and host configuration for better
coverage, and advise on remediation. It works fully without it.

- **Your choice at setup.** When the tool is set up, it asks whether to turn
  the advisor on and explains what would be sent and to whom. Installations
  set up without anyone answering questions leave it off unless the
  configuration file turns it on. `checker config` or the web interface's
  Settings page changes the choice later, and every change made with either is
  recorded with when it was made. The command line records the machine account
  that made it, and the page's activity record names the person. Edits made to
  the configuration file by hand are not recorded.
- **Your account, your provider.** The advisor uses your organization's own
  account with the AI provider, or a model you run yourself on your own
  hardware. Data sent goes from your machine to that provider under your
  agreement with them. NouriLoop LLC does not pass it on, see it or keep it.
  The API key is read from where you keep it (an environment variable, the
  operating system's keyring, or a command such as a password manager's) only
  when a request is about to be sent; it is never written to the
  configuration, a log or the evidence store.
- **Only when asked.** Nothing is sent until an operator runs `checker
  advise`. `checker advise --show` prints exactly what would be sent, after
  redaction (apart from the placeholders' random tag, which each run draws
  afresh), and sends nothing; with a fallback model, it says who would receive
  the request but doesn't print that model's form of it. Before sending, the
  tool shows the likely cost and asks when it is above the limit your
  organization set, or when the cost isn't known.
- **What is sent:** the server's operating system and kernel version, the
  host's group in your inventory, findings with their titles, summaries, the
  accounts and paths they involve, scores and when they were first and last
  seen, how findings link into chains, short masked excerpts of the evidence
  behind them, notes on what the analysis is unsure of, the related whitelist
  rules, and the coverage gaps (which sources were missing, and how far back
  each log reaches). Never whole log files, and never passwords or keys.
  Whitelist rules are sent with the reasons written in them, so those reasons
  should describe the activity, not name people.
- **Redaction**, set by your organization:
  - *pseudonymize* (the default when the advisor is turned on) — server names
    and their domains, IP addresses, usernames, the host's group in your
    inventory, email addresses and SSH key fingerprints are replaced with
    placeholders such as `USER-2-7f3a` before sending, and restored on your
    machine when the answer returns. The placeholders are made fresh for each
    run, so the provider can't connect one run to another by name; your
    encrypted record keeps the request as it was sent. Names that appear only
    in free text (another company's domain in a log line, a person's name in a
    comment) aren't recognised, and common system accounts such as `root` are
    kept as they are, and so are the host's own group names (`wheel`, or ones
    your organization made);
  - *strict* — only the kinds of finding, counts, scores and kinds of coverage
    gap are sent;
  - *none* — excerpts are sent as collected (after secret masking).
- **Declined requests.** An AI model's safety checks may decline security
  content now and then. Your organization chooses what happens next: nothing
  more; a re-run on the model the same provider recommends for that kind of
  decline (the default, with Anthropic); or a re-run on a fallback model it
  names, which may be another provider's or its own. The fallback model
  receives the same request, with the same redaction and placeholders, and
  `checker config show` says who would receive it. The report names the model
  that declined and the model that answered.
- **Where it runs.** Organizations that must keep processing in one geography
  can set it (for example, the United States) where the provider offers that.
  A model on the machine running the tool is reached directly, never through a
  proxy.
- **Advice only.** The advisor cannot connect to any server and cannot change
  any setting, score or whitelist. Its proposals are written to a file for a
  person to review. A person can approve a proposal from the web interface,
  which first shows what it would hide and asks for their password, and records
  it in their name. Suggested settings are shown as commands for a person to
  run. The tool never offers a rule that whitelists a critical finding or
  one that is part of a chain; a model's suggestion of one is set aside, and
  the report says so. Every report section written by the advisor is labelled
  with the model, the redaction setting and the time, and says when the
  analysis it read isn't the one the report shows.
- **A record of what left.** Each request and its answer are stored encrypted
  with your evidence key, in an append-only record, so your organization can
  show afterwards exactly what was sent and to whom. They are deleted with the
  evidence they were about. A request quotes the host's baseline where a
  finding compares with it, so purging only the baseline leaves those quotes
  in later records until those are purged too. Whitelist proposals are files
  readable only by their owner, with real names in them, and are deleted with
  the same evidence while they keep the name they were written under; a copy
  moved or renamed, and rules copied into a whitelist, are yours to remove.
- **Untrusted text.** Log content can be written by attackers (for example, a
  username or web address crafted to mislead an AI). It is always passed to
  the advisor marked as data to examine, never as instructions, and every
  answer is checked against the evidence before anyone sees it.

## 10. What leaves your organization

Nothing, unless you choose one of these:

- the AI advisor (section 9);
- optional reputation checks, which send IP addresses or file fingerprints
  (never files) to a reputation service you configure;
- notifications from `checker run`, if you set a notify command: the tool
  runs your command on your machine and gives it a short summary in the
  tool's own words (host names, bands, check names, finding titles and the
  report's path; never evidence or text from a host); where that command
  sends it is your choice.

The tool has no telemetry, usage reporting or licence check, and it never
contacts NouriLoop LLC on its own. Threat packs (section 11) are downloaded
only when someone runs `checker packs pull` or asks for them on a page of the
web interface, over HTTPS, from NouriLoop's public repository on GitHub or from
a mirror you name. That request carries
what any web request does, such as your address, and none of your evidence.

## 11. Threat packs and trust

Threat packs teach the tool about specific new threats: which package versions
are vulnerable, which settings help, and which signs of attack to look for. A
pack is data, never code. It runs nothing on your servers and doesn't change
what the collector reads; it is applied on your own machine, to evidence
already collected.

**Signing.** Packs are published in a separate public repository and signed by
hand. NouriLoop LLC has two keys, both kept off any server: a root key, which
signs only the list of trusted pack keys, and a pack key, which signs packs. A
pack key that leaks or is lost can be replaced by a new list, without a new
release of the tool. The tool refuses any pack whose signature it cannot
verify, an older version of a pack it has already accepted, and changed content
under an old version number. Your organization can also sign its own private
packs with its own key and tell the tool to trust that key; those packs are
trusted only by your installation.

**What a pack changes.** A host found exposed to a pack's threat starts from a
higher probability of compromise, in proportion to how long it was exposed;
exposure alone is never treated as a sign of compromise. A pack can also add
findings of its own, and give more weight to the tool's built-in findings,
within fixed limits.

**Which servers.** Every pack in force applies to every server unless you say
otherwise. You can keep packs off a server, a group or all servers. Changes made
with the tool's commands or pages are recorded, with when they were made; pages
also record the person. Stopping a pack or putting it back from a page is in the
activity record. Edits made to its files by hand are not recorded. An analysis says which packs it applied, and which
it held back and why.

**Staying current.** The index of packs is signed again at least monthly, and
the tool warns when the copy it finds is more than 30 days old. It cannot tell
you about a pack it has not been able to download, so a site that never pulls
gets no new packs. A key's revocation also reaches you only through a pull or a
new release of the tool.

## 12. Security of the tool itself

- The collector and the rest of the tool are open source (AGPL-3.0), so
  anyone can inspect them.
- Releases and threat packs are signed.
- Dependencies are kept few and pinned.
- Text collected from a server is treated as hostile, since a compromised
  server can write anything into its logs. In reports and the web interface it
  is escaped and invisible characters are shown, and pages run no scripts except
  those the tool ships and load nothing from other sites.
- To report a vulnerability in the tool, see `SECURITY.md`.

## 13. Your responsibilities

The tool gives you control of the data it collects, so these remain yours:

- having authority to assess the servers you check;
- telling staff or users about monitoring where your policies or local law
  require it;
- your agreement with any AI or reputation provider you choose to use;
- keeping the evidence encryption key and reports safe, and setting a
  retention period that meets your own obligations.

## 14. Limits of the tool, and responsibility for its use

- **No guarantee.** The software is provided under the AGPL-3.0 licence "as
  is", without warranty of any kind, and NouriLoop LLC's liability is limited
  as set out in sections 15 and 16 of that licence. Those licence terms are
  the binding ones; this section explains them in plain words.
- **Findings are estimates.** A probability of compromise is an informed
  estimate from the evidence available, not a certainty. A report with no
  findings does not prove a server is clean: attackers can avoid or remove
  evidence, logs may be missing, and no set of checks covers every technique.
  A high score is a reason to investigate, not proof of an intrusion.
- **Advice is advice.** Remediation guidance, whether from the tool's rules or
  the AI advisor, must be judged by qualified people against your own systems
  before anyone acts on it.
- **Use is the user's responsibility.** NouriLoop LLC does not control who runs
  the software or against which systems. Anyone who uses it, or a modified
  version of it, is responsible for having the authority to do so and for
  complying with the law. NouriLoop LLC is not responsible for unauthorized or
  unlawful use.
- **Modified versions.** This policy describes the software as NouriLoop LLC
  publishes it. A modified version may behave differently; the collector
  fingerprint stored with each collection shows whether the published
  collector was the one that ran.

## 15. Changes to this policy

Each release includes the policy that applies to it. Changes are listed in the
release notes, and any change that sends more data anywhere, or collects a new
kind of data by default, is called out at the top of those notes.

## 16. Contact

NouriLoop LLC, Astoria, Oregon. Security reports: security@nouriloop.com
(see `SECURITY.md`). Other questions: info@nouriloop.com.
