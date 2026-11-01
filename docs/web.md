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
and sends any notification. If you started it you can leave the page, or stop it. One runs at a time,
including any on a timer, and one still going after 4 hours is ended, since it may be waiting for a prompt
nobody can answer. A server's page can also work its results out again from what was last collected,
connecting to nothing, which is useful after a threat update.

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

## What it keeps

`web.db` in the checker's home, owner-only: accounts with hashed passwords, two-factor secrets and
recovery codes, sessions, failed
logins for the last 15 minutes with their usernames and addresses, the times of wrong passwords and codes (never what was typed), the latest 50 checks started from a page, and the activity record below. Each
of those checks' output is in the `checks` folder in the home, owner-only, and goes when the check is let go: it holds what the
command line prints, which can quote an error a server sent, and never passwords. No evidence is ever copied
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
