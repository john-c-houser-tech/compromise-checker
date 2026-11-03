# Installing

Compromise Checker needs a machine of its own: it holds keys that act as an administrator on every server it
checks. It installs on x86 machines running Ubuntu 24.04 or 26.04, or Rocky Linux 9 or 10. Close relatives of
those, such as Linux Mint, aren't supported yet, and the installer stops with a message.

The installer asks whether people will use the tool from other computers. If not, it answers only on the
machine itself, for a browser there. If so, it needs [a web address](#a-web-address) of its own.

## What the installer does

A release's install page gives one line to paste. In a new private folder, it downloads `install.py`, checks it
against a hash on the page, and runs it with `sudo python3 -I`, removing the folder afterwards. That hash is what protects the installer, since the file
comes from the same place as the rest of the release. So the line has to be copied from the install page, not
from anywhere else. `-I` keeps Python from running code from the folder you're in, and the installer shuts
out what's beside it as well. In order, it:

1. **Checks the release's signature,** before running anything from it. The installer knows the version it's
   for and the release key, so it refuses any other release, or one signed by anyone else. A file that doesn't
   match what was signed is refused. It can't tell you a newer version exists, so use the current install page.
2. **Looks for other use.** Programs that other computers can reach, over TCP or UDP (a VPN such as WireGuard
   among them, since the firewall would cut it off), and other people's login accounts, are listed with why
   they matter. It stops unless you type a short sentence to go ahead. This is a nudge rather
   than a guarantee: it can't see everything. Nothing has been changed up to this point. If something else is
   using port 8088, it stops with no way past.
3. **Asks about SSH,** after asking about [a web address](#a-web-address): whether to turn off password
   logins, root logins, and to block addresses that keep trying to log in. Each is asked separately, and Enter
   means no. [Locking the machine down](#locking-the-machine-down)
   says what each does and when one isn't offered. Nothing is changed yet.
4. **Installs what's needed** from the system's own packages: a Python the tool can run on, the libraries
   PDF reports use, the firewall, and what installs security updates.
5. **Turns on a firewall and automatic security updates,** saying as it does each one.
6. **Makes an account** called `compromise-checker`, which nobody can log in to, with a private folder at
   `/var/lib/compromise-checker`. If an account by that name already exists and doesn't look like one the
   installer made, it stops, rather than hand that account the tool's keys.
7. **Installs the tool** in `/opt/compromise-checker`, with exactly the dependency versions the release lists.
   Each is checked against its hash, and none is built from source. The tool's account can't change these files.
8. **Starts the web interface** as a service, as that account, answering only on this machine. It starts again
   after a reboot. That account's own systemd stays running, for the daily check.
9. **Turns sleep off,** so a daily check isn't missed. If the machine was off when a check was due, it runs when
   the machine next starts, and the page says when a server hasn't been checked for a few days.
10. **Makes the SSH changes you agreed to,** checking that SSH takes them first. Logins already open stay open.
11. **Gives you a link** for creating the first account. It works once, within an hour.

If it stops part way, run it again to carry on, whether or not an account has been made in the meantime. Once
it has finished, running it again changes nothing.

## A web address

For people to use it from other computers, the tool needs a name of its own, such as `checker.example.org`, and
the machine has to be reachable from the internet: a cloud server, typically. A PC behind a home or office
router can't get a certificate, and the installer says so rather than trying.

You'll be asked for the name, and whether only some addresses, such as your office's, may reach the page.
Before changing anything, the installer checks that the name leads to this machine. Some cloud providers
give a machine only a private address and pass a public one on to it, so if the name leads elsewhere, the
installer asks each address the name gives for a page, and sees whether the request arrives here. If a
firewall is running here, it lets port 80 in for that moment only. If this machine's own `/etc/hosts` gives
the name an address, it stops and says so, since it couldn't see what everyone else sees. A name that leads to a
private address, which the internet can't reach, is refused too. If the name doesn't exist yet, it shows the DNS record to add and waits for it. If it leads
somewhere else, it stops.

It then sets up Apache, from the system's own packages, in front of the tool:

- Apache gets a certificate from Let's Encrypt for the name, with its own `mod_md` module, and renews it. An hourly
  reload lets Apache use a new certificate. Let's Encrypt checks that the name leads to this machine, and
  the name appears in public certificate logs. The account it makes there gives `webmaster@` and the name as
  its contact, since `mod_md` needs one, so nothing personal is sent.
- It answers on port 443, and port 80 only sends people to 443 and lets Let's Encrypt check the name. HTTP/2 is
  off. Ports 80 and 443 are opened in the firewall.
- The tool still listens only on this machine. Apache passes requests to it with a secret only they share, so
  nothing else on the machine can pass for Apache.
- On Rocky, SELinux keeps Apache confined. The narrowest switch that lets it connect out at all is turned
  on: `httpd_graceful_shutdown`, which, despite its name, only lets it reach web ports, Let's Encrypt's
  included. The tool's port is added to those.
- Apache keeps no access log for the name, since a setup link would be in it, and doesn't log the requests
  it refuses. It only passes on requests for the name itself.
- With a limit, only those addresses get past Apache to the page. Let's Encrypt can still reach port 80, so
  renewals keep working.

If Let's Encrypt can't reach the machine, the installer says so at the end, and Apache keeps trying. The page
doesn't work until it succeeds, and Apache starts using the certificate within the hour after it arrives. The usual cause
is a firewall at the hosting provider that blocks port 80 or 443.

An installed machine can't be switched between the two yet. If an install with a web address stops part way and
is run again with the other answer, the installer takes down what it had set up for the web address, and only
that: Apache is only stopped if it came with the installer, and only the firewall openings it made are closed.

Without a terminal to ask in, `--web-address NAME` and `--allow "ADDRESSES"` give the answers instead.

## Locking the machine down

Done every time, and said as it's done:

- **A firewall** that lets in only SSH, and ports 80 and 443 with a web address. Ubuntu's is `ufw` and Rocky's
  is `firewalld`. Before it starts, it lets in every port SSH is listening on, so the session you're
  installing from isn't cut off. On Rocky, the opening for Cockpit, the system's own web console, is closed.
  Where an interface or some source addresses have a firewalld zone of their own, SSH is let in there too.
  Rules a stopped `ufw` saved from before come back with it, so any saved rule for SSH's port is replaced,
  and SSH's own goes in front of the rest. If SSH isn't running, nothing is let in
  for it, and you'd need to open its port if you turn SSH on later. If SSH is running but its port can't be
  found, no firewall is turned on, and the installer says so.
  If a firewall is already running, whether `ufw`, `firewalld`, or rules loaded by `nftables.service` or
  `iptables`, its rules are kept as they are, and the installer lists what else `ufw` or `firewalld` lets in,
  for you to close what this machine doesn't need.
- **Automatic security updates,** with the system's own tools: `unattended-upgrades` on Ubuntu, and
  `dnf-automatic` on Rocky, from its own settings file so the system's `automatic.conf` is left alone. If
  updates already install by themselves, that's left as it is. The machine is never restarted for an update.
  The page says when one is waiting for a restart, so you can choose the moment.

Each only if you say yes, asked separately:

- **SSH passwords off.** Then only someone holding a key can log in, and a key can't be guessed. It's only
  offered if an administrator account has logged in here with a key that SSH would still let in today. An
  administrator is root, or an account in the `sudo`, `admin` or `wheel` group that can run anything through
  `sudo`. The login is taken from what SSH itself logged, which nobody else on the machine can write. It's
  then checked against SSH's settings as they stand, for that account and the address it came from: root
  shut out, keys turned off, `AllowUsers` and the like, and `Match` sections. The key has to still be there,
  and not be one held to a single command, and SSH mustn't want a one-time code after the key, which goes
  with the passwords. If it isn't offered, the installer says why. If SSH's settings can't be read at all,
  nothing about SSH is asked or changed.
- **Root login over SSH off.** Administrators then log in as themselves and use `sudo`, which leaves a record of
  who did what. It's only offered if another administrator account has logged in here in a way SSH would
  still let in, with a key if passwords are going off, so root isn't the only way in.
- **Blocking addresses that keep trying to log in.** Where SSH can do this itself (Ubuntu 26.04 and Rocky 10,
  with OpenSSH 9.8 or later), it holds off an address that keeps failing to log in, for longer each time.
  That's usually on already, and then the installer just says so. Ubuntu 24.04 and Rocky 9 have an older SSH,
  so the firewall does it instead: an address that opens SSH connections quickly, about 6 in 30 seconds, has
  to wait. That could slow a tool that logs in to this machine many times in a row. With a `ufw` the installer
  set up, that's `ufw limit`. Elsewhere, including a firewall that was already running, it's a small table of
  `nftables` rules, `/etc/nftables/compromise-checker-ssh-limit.nft`, loaded by
  `compromise-checker-ssh-limit.service`, which only ever holds connections back and never lets anything in.
  The `nftables` rules count IPv6 addresses by the /64 they're in, and `ufw limit` counts each address. It
  only limits connections to this machine, never the
  tool's own connections to the servers it checks.

The SSH changes go in `/etc/ssh/sshd_config.d/01-compromise-checker.conf`. SSH takes the first value it reads,
so this file comes before the one a cloud image adds. The installer checks that SSH accepts the file and that
the settings took, and if not, it puts the file back as it was and says why. If a `Match` section in SSH's
settings still lets an account seen in the log use a password, it says that too. Without a terminal to ask in,
`--ssh-passwords-off`, `--root-login-off` and `--block-login-failures` give the answers, with the same checks.

A small service, `compromise-checker-status`, runs as root every hour and notes two things for the web page:
whether SSH still accepts passwords, and whether an update is waiting for a restart. People with full access
see a notice for each, and another if those notes are over three hours old. The note about passwords is SSH's
setting for everyone; it doesn't see a `Match` section that turns passwords back on for some.

### Turning SSH passwords off later

Log in once with your key, as an administrator, so you know it works. Then, as root, add these two lines to
`/etc/ssh/sshd_config.d/01-compromise-checker.conf`, making the file if it isn't there:

    PasswordAuthentication no
    KbdInteractiveAuthentication no

Check with `sudo sshd -t`, then `sudo systemctl try-reload-or-restart ssh` on Ubuntu or
`sudo systemctl reload sshd` on Rocky.
Keep the session you made the change from open, and check that a new key login still works before closing it.
The notice goes within the hour.

## The setup link

    sudo /usr/local/sbin/compromise-checker-link

This makes a new link, and any link before it stops working. A restart of the machine or the web interface also
replaces the link, so use this command if yours stops working. Once there's an account, no link is needed.

## What it doesn't do yet

- It doesn't back up the evidence. If the machine is lost, so is each server's history, and the tool starts again
  from what each server looks like that day.
