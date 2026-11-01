# The web interface

For people who won't use a command line. Install the extra and start it:

    pip install -e '.[web]'
    checker web

The first time, it prints a link that works once, for an hour. Open it and create your
account. Each restart replaces the link until an account exists. After that, sign in at the
address it prints.

So far it shows the fleet, most worrying first ([the fleet at a glance](report.md)). A server
reads as having no strong signs only if its score is Low and nothing else is wrong: an open
threat, serious problems, warnings from the check before, missing logs or a stale result all
take that away. Pages that show results only read: the evidence store is opened read-only.

**Checks** starts a check from a page and shows how it's going. It's the same run as `checker run
--unattended`, in a process of its own: it collects, analyzes, writes a report, purges what has expired
and sends any notification. You can leave the page while it runs, and anyone signed in can stop it: what
it has collected so far is kept and recorded, so a purge can find it. One check runs at a time, including
any on a timer, and one still going after 4 hours is ended, since it may be waiting for a prompt nobody
can answer. A restart of the web server stops a check that's running, keeping what it collected. A server's page can also work its
results out again from what was last collected, connecting to nothing, which is useful after a threat
update.

A server that logs in with a typed password or uses sudo's asks for it on the page. It goes to that one
check and isn't kept. One that uses a password in the system's keyring, or a key file with no passphrase,
just runs. One that needs the SSH agent works only if the server was started where it can reach one, and
the page says why not if it can't. If an agent asks for a passphrase, nobody sees the request: use a key
already unlocked, or Stop the check.

Each server has its own page, with what was found in plain words, and an evidence page for
whoever looks into it: the excerpts behind each finding, what happened in order, and the
collection's fingerprints and chain of custody. Pages show what is stored, and if part of a
check's details isn't stored they say so. Text from a server is boxed apart, since an intruder
could have written it.

Each server's page, and the evidence behind it, from a demo fleet of throwaway servers attacked on
purpose. These are real results from this tool, with addresses replaced:

![A server's page](screenshots/host.png)

![The evidence behind its findings](screenshots/evidence.png)

![Known threats](screenshots/threats.png)

To take them again: `tests/integration/demo_fleet.py` makes the fleet (about 3 cents of Linode time),
and `tests/integration/screenshots.py` photographs it. Every page is scrubbed of public addresses on
its way to the browser, and the run stops if any survive.

## Where it listens

By default, on this machine only (`127.0.0.1:8088`). Anyone with an account on this machine
can reach that address, which is why it asks for a login even there.

- **Behind a proxy on this machine** that provides https (Caddy, nginx):
  `checker web --public-url https://checker.example`. Only that address is accepted, and cookies
  are sent only over https. The proxy must add the client's address as the last entry of
  `X-Forwarded-For`, which Caddy and a normal nginx setup do, and should buffer request bodies. The
  address in the activity record is only as good as that proxy. Anyone with an account on this machine
  can connect to the tool's port directly and claim any address, which gets around the limits on guessing
  a login and puts a false address in the record, so use this on a machine only you can sign in to.
- **From other machines, without a proxy:**
  `checker web --bind 0.0.0.0:443 --tls-cert CERT --tls-key KEY --public-url https://checker.example`.
  It refuses to listen beyond this machine without TLS, and refuses an http address for another
  machine, since logins and evidence would cross the network unencrypted.

**Decide what's normal** on a server's page is for the two choices that can hide a real change, so each
shows what it would hide first, and takes your password, and a code if two-factor is on. It's worked out
again when you confirm it: if that differs from what you saw, you're asked to look again.

- **Accept how it is now.** The latest check becomes the baseline, with your reason, so what changed since
  the old one stops being reported as changed. It has to be the check you were shown: a newer one means
  looking again. A server assessed High or Critical gets a warning, not a refusal, since you may know why.
- **The AI advisor's whitelist rules.** A rule hides findings from then on. Each shows what it would hide
  in the last 30 days' results that could be compared, on every server it would reach, and says how many
  that was. It can't be approved if a server it reaches has no check, or its latest can't be compared; if
  it would hide a critical finding; if a server it reaches is assessed High or Critical or has a chain of
  findings; or if it's a rule for a check only ever written by hand, has no narrowing, has expired or lasts
  over 90 days. An approved rule goes in the same
  file you'd edit by hand ([whitelists](whitelists.md)), in your name, with what's already there left as it
  was; if the tool can't add to that file safely, it says so and changes nothing. Refusing one takes it out
  of the proposals, and a file that can't be read can be discarded. If the advisor is on, you can ask it for
  rules from there, with your password since that costs money. A request that may cost more than
  `advisor.max_cost_per_run`, or whose price isn't known, isn't sent, and the page says so.

Decisions take effect the next time results are worked out.

## What it keeps

`web.db` in the checker's home, owner-only: accounts with hashed passwords, two-factor secrets and
recovery codes, sessions, failed
logins for the last 15 minutes with their usernames and addresses, the times of wrong passwords and codes (never what was typed), when the latest 50 checks started from a page ran and how they ended, and the activity record below.
What a check reports while it runs, which can quote an error a server sent but not findings or passwords,
stays in the web server's memory, and goes when it restarts. No evidence is ever copied
there. `keys/web-secret.txt` signs sessions; deleting it signs everyone out. Evidence is decrypted
in memory for each page, with the same key the command line uses, and pages tell browsers not to
keep them. There is no access log; only errors in the tool itself go to its standard error.

## The activity record

The Activity page lists who signed in and out, who viewed which server's results and evidence, and each
action taken from these pages, with when and from which address. It's permanent and append-only, in the
tool's own words, and holds no evidence. It tells you what happened; anyone with full control of this
machine could still alter it, so it isn't protection against that. If an action can't be recorded as
started, it doesn't happen. A line that says started with no result after it means the tool stopped, or
couldn't write down how it ended, so check what it did.

Viewing results and evidence goes ahead even when the record can't be written, for example on a full
disk, since you may need them most then. That leaves a line on the tool's standard error instead. Signing
out goes ahead too, but on a full disk it only clears this browser: the session stays valid on the server
until it expires, up to 8 hours, and the page says so. `checker web-password` ends it once there's space.

Anything that changes what later findings mean, or removes data, asks for your password again, even
when you're signed in. Five wrong passwords sign that session out. A browser's password manager may
fill the box in for whoever is at the keyboard, so don't leave a signed-in browser open.

## Two-factor sign-in

Signing in can take a six-digit code from an authenticator app as well as your password, so a stolen
password isn't enough. Any app that does time-based codes works.

- **When it's required:** whenever another machine can reach the server, which means it listens beyond
  this machine or its `--public-url` isn't a name on this machine (`localhost`, `*.localhost`, a loopback
  address). Until an account has set it up, it can't see anything.
- **When it's optional:** when only this machine can reach the server. Every page asks you to turn it on
  until you do, because anyone with an account on this machine can reach that address too.
- **Lost your phone?** You get ten recovery codes when you turn it on, each good once, and they're shown
  only then. Pages remind you until you say you've saved them. It takes one to sign in without your
  phone and another to change anything, unless it was your last. If they're gone too, whoever owns the
  checker's home can run `checker web-password USERNAME` and then `checker web-two-factor-off USERNAME`
  on this machine, in that order, since anyone who knows the old password could otherwise set it up as
  theirs. Both end the account's sessions, and the activity record notes them.
- **Someone may have your password** if a sign-in asks for a code when you never set it up, if setup keeps
  saying it has ended, if you're told to wait after wrong codes you didn't type, or if the Activity page
  shows them. Each wrong code makes the next try wait longer, up to about 9 minutes, even with the right
  code, so anyone with the password can slow you down. On the machine, as the user who runs the tool, run
  `checker web-password USERNAME`, which ends that and their sessions. If you still can't get past the
  code, because they set it up with their phone, run `checker web-two-factor-off USERNAME` next.
- **Moving to a new phone:** Sign-in security, in the menu, turns it off so you can set it up again.

With two-factor on, anything that asks for your password again asks for a code as well. A code works
only once, so after using one, wait for the next. Five wrong codes end the session. With a stolen
password, someone can try about 170 codes a day before that wait stops them, each one shown on the Activity
page, so don't leave wrong codes you didn't type unexplained. The secrets and recovery codes are stored readable in `web.db`, since the tool has to check against them: treat a
copy of that file, or a backup of it, as you would a password.

## First setup

The first time `checker web` starts, in an empty home, it sets itself up: an evidence key, a database,
nothing optional collected and the AI advisor off. It prints where the key is and the one-time link for
the first account. If settings go missing from a home with a key or evidence in it, it refuses, and says to
restore them: a new key would make everything stored unreadable. `checker init` is still there
for anyone who wants to answer its questions first, or keep the private key elsewhere (`--recipient`).

The First setup page then goes through what's next, working out where you are from what's really there:
back up the evidence key, choose what's collected, make this machine's key, add a server, run the
commands it gives you on that server, confirm its identity, and run a first check.

- **The evidence key isn't offered as a download.** The page says where the file is. A copy in a browser's
  downloads folder is a worse place for it than where it already is.
- **This machine's key** is made only when you ask, in `keys/scanner_ed25519`, readable only by the tool's
  account. It has no passphrase, so daily checks can use it, which makes that file a credential for
  acting as an administrator on every server that accepts it. It's never replaced by the page.
- **The commands** are for a new, plainly named account logging in with a key file, using one sudo rule, and
  stop without changing anything if that account already exists. For anything else, the page says so and
  points to [setting up a scanner account](scanner-account.md).

`tests/integration/first_setup_proof.py` runs the whole path against a real sshd in a container.

## Managing servers

The Manage page lists every server, and adds, changes and removes them. Each of those needs your
password again, and a code if two-factor sign-in is on, and goes in the activity record. A change to
a server's settings also goes in `checker config history`, as `hosts.<name>` with what changed, and
so do adding and removing one, with its settings.

A server's name can't change, since its results are filed under it. Adding a name that has earlier
results takes saying it's the same server, because new results would be compared with the old ones.
Removing a server stops its checks and keeps its results, until a purge after their retention period or
you delete them.
Its whitelist rules and confirmed key stay too, and a name with rules kept counts as earlier results.

A group exists while a server is in it. There's no separate list of groups to keep up. Moving a
server into a group brings in that group's whitelist rules and threat update settings, and those
can hide findings.

### Confirming a server's identity

A server can't be checked from these pages until its SSH host key is confirmed, so that nothing is sent to a machine
pretending to be it. The page asks the server which kind of key it has and gives you a command to
run on the server. Paste what it prints, and the tool compares that with a fresh answer from the
server. The page doesn't show the fingerprint it received until then: copying it from here into the
box would prove nothing, because someone in the middle would have sent it.

Run the command on the server itself, from its provider's console or through someone who already
looks after it. A key that differs from the one confirmed before gets a warning, and replacing it
takes saying that you know why it changed. Keys are kept per address, so a new address or port needs
confirming unless a server there has been confirmed already.

Asking for a key and comparing it are the only things on these pages that contact a server, and only
one in the list. Keys listed in the file by hand as hashed lines aren't recognized by these pages:
keep to the keys the tool wrote there.

## Threat updates and settings

Manage also gets the latest threat updates, stops using one and puts it back, and chooses which apply
to all servers, a group or one server. Getting updates contacts only the source in the settings, takes
only what a trusted key signed, and needs no password, like starting a check. It can also stop using an
update, if its publisher withdrew it or its signing key is no longer trusted, and the page says so. It
applies the next time results are worked out. The rest needs your password again.

The Settings page covers what's collected, how long it's kept, the starting estimate and the AI
advisor. Several changes saved together go in or fail together, and each is in `checker config history`.

Some things stay on the command line, and the pages only say whether they're set, never what they say:

- what runs a command on this machine: the notify command, and an API key read by running a command;
- what sends data or keys to another address: another advisor server, a second model for declined
  requests, and another source of threat updates;
- adding a threat update from a file, and trusting your organization's own signing key.

From a form, these would let anyone with an account run programs here, collect the API key, or choose
who may sign what the tool believes.

## Checking every day, and deleting evidence

Manage can set a check to run every day at a time you choose, and stop it. That's the same run as
`checker schedule install`: it checks every server, works out results, writes a report, and deletes what's
past its retention period. It uses a timer on this machine, under the account the web server runs as,
and keeps running when the web server is stopped, until someone stops it. On Linux that needs a user
session, so a web server started as a system service can't set it, and lingering to run with nobody
logged in. On a Mac it runs only while someone is logged in there. The page says so, and lists servers
a daily check can't reach.

Manage can also delete stored evidence, for one server, before a date, or past its retention period. It
shows what would go first, then needs your password and the word `purge` typed. If what would go has
changed since you looked, it asks you to look again. It won't start during a check started from a page,
a daily check, or `checker run`. The record of what was deleted stays. See [retention](retention.md).

If you think a server was broken into, stop the daily check and raise the days kept in Settings: a daily
check, and any check started from a page, delete what's past them.

## How it protects you

- **Two-factor sign-in,** above. With only a password so far, nothing opens but the second step, or
  setting it up if that's still to be done.
- **Passwords:** at least 12 characters, not common, not all digits, not like the username. Five
  failed logins for a name from one address, or twenty from one address, stop further tries from
  there for 15 minutes, even with the right password. Without a proxy, everyone on this machine
  counts as one address, so another local user could lock you out for that long. If you lose a
  password, `checker web-password USERNAME` sets a new one and notes it in the activity record. Don't
  delete `web.db` for this: the activity record goes with it.
- **Host text is treated as hostile.** A compromised server can put anything in its logs, and that
  text reaches a signed-in browser. Everything printed is escaped, invisible characters are shown,
  and the content security policy allows no scripts at all and nothing from other sites.
- **Sessions** last 8 hours or until the browser closes. Cookies can't be read by scripts or sent
  from other sites.
- **Nothing is fetched from elsewhere:** no analytics or content delivery networks. The font,
  Atkinson Hyperlegible from the Braille Institute, ships with the tool under the SIL Open Font
  License (`checker/web/static/fonts/OFL.txt`).

The name shown can be changed with the environment variable `CHECKER_PRODUCT_NAME`.
