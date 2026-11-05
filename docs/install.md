# Installing

Compromise Checker needs a machine of its own: it holds keys that act as an administrator on every server it
checks. It installs on x86 machines running Ubuntu 24.04 or 26.04, or Rocky Linux 9 or 10. Close relatives of
those, such as Linux Mint, aren't supported yet, and the installer stops with a message.

It needs at least 1 GB of memory and 5 GB of free disk. Measured on new 1 GB servers (the smallest Linode),
right after install: the tool used about 100 to 200 MB of memory and added 430 to 600 MB of disk, and the install
took 1 to 1.5 minutes on Ubuntu and Rocky 9, and about 3 minutes on Rocky 10. Checking servers and making PDF
reports use more while they run. The installer doesn't enforce a minimum.

The installer asks whether people will use the tool from other computers. If not, it answers only on the
machine itself, for a browser there. If so, it needs [a web address](#a-web-address) of its own.

## What the installer does

A release's install page gives one line to paste. For 0.1.0 it is at
<https://nouriloop.com/work/compromise-checker/install/>. In a new private folder, it downloads `install.py`, checks it
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
  is `firewalld`. Rocky runs `firewalld` from the start: while it's just as the system set it up, it's set up
  like a new one. Before it starts, it lets in every port SSH is listening on, so the session you're
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
  shut out, keys turned off, `AllowUsers` and the like, `ForceCommand` or `ChrootDirectory`, which keep a
  login from administering the machine, `AuthenticationMethods`, and `Match` sections. The very key that logged
  in, by its fingerprint, has to still be where SSH looks for it, and not be one held to a single command
  or set to expire, or limited to some addresses (`from=`), and the account mustn't have expired, and SSH mustn't want a one-time code after the key, which goes
  with the passwords. If it isn't offered, the installer says why. If SSH's settings can't be read at all,
  nothing about SSH is asked or changed.
- **Root login over SSH off.** Administrators then log in as themselves and use `sudo`, which leaves a record of
  who did what. It's only offered if another administrator account has logged in here in a way SSH would
  still let in, with a key if passwords are going off, so root isn't the only way in.
- **Blocking addresses that keep trying to log in.** Where SSH can do this itself (Ubuntu 26.04 and Rocky 10,
  with OpenSSH 9.8 or later), it holds off an address that keeps failing to log in, for longer each time.
  That's usually on already, and then the installer just says so. Rocky 9's SSH is older, but has had it
  added. Ubuntu 24.04's hasn't, so the firewall does it instead: an address that opens SSH connections
  quickly, about 6 in 30 seconds, has to wait. That could slow a tool that logs in to this machine many times in a row. With a `ufw` the installer
  set up, that's `ufw limit`. Elsewhere, including a firewall that was already running, it's a small table of
  `nftables` rules, `/etc/nftables/compromise-checker-ssh-limit.nft`, loaded by
  `compromise-checker-ssh-limit.service`, which only ever holds connections back and never lets anything in.
  The `nftables` rules count IPv6 addresses by the /64 they're in, and `ufw limit` counts each address. It
  only limits connections to this machine, never the
  tool's own connections to the servers it checks.

The SSH changes go in `/etc/ssh/sshd_config.d/01-compromise-checker.conf`. SSH takes the first value it reads,
so this file comes before the one a cloud image adds. The installer checks that SSH accepts the file and that
the settings took, then reloads SSH. If any of that fails, it puts the file back as it was and says why. If a `Match` section in SSH's
settings still lets an account seen in the log use a password, or root log in, it says that too. Without a terminal to ask in,
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

## Backing up the evidence key

Everything the tool stores is encrypted to one key, made on this machine the first time the tool starts.
Without it, nothing stored can be read, by anyone. Once the first account exists, First setup points to the
key's page, under Manage: a person with full access confirms with their password, and a code if two-factor
sign-in is on, and the key appears as one line to paste into a password manager. Each showing goes in the
activity record. It's never offered as a download. The file is at
`/var/lib/compromise-checker/data/keys/evidence-identity.txt`, readable only by the tool's account, for
anyone who would rather copy that.

The tool doesn't back up the evidence itself. If this machine is lost, or its disk fails, each server's history
goes with it, and the tool starts again from what each server looks like the day it's next checked. A backed-up
key lets you read a copy of the evidence you kept yourself; it doesn't bring the evidence back. If the machine
is at a hosting provider, the provider's machine backups are the simplest protection, if your organization
accepts that the provider then holds a copy. Such a backup holds the key and the evidence together, so whoever
can restore it can read everything: protect it like the evidence.

On a machine used only from itself, usually a PC on a home or office connection, the page that gives the
commands for setting up a server warns against limiting this machine's key to its address: that kind of
address can change, and when it does, every server limited to it refuses the key until an administrator there
changes the address in the key's line in the account's `authorized_keys` file, or takes the account away and
sets it up again. The setup commands alone won't do it: they stop when the account already exists.

## Linode's form

On Linode, the same install can be done with no terminal, from a StackScript NouriLoop publishes under the
name `compromise-checker`: in Cloud Manager, under StackScripts, Community StackScripts. Its form asks for a web
address, which is needed because a Linode has no browser of its own, optionally the addresses allowed to open
the page, and the three SSH questions as yes or no, all set to no. Nothing it asks is secret. For a trial, the
web address `auto` makes a name at sslip.io from the Linode's address, which Let's Encrypt can give a
certificate for. That name, and so the address in it, then appears in public certificate logs, and it depends
on sslip.io's name service; for real use, give a name you own and point its DNS record at the Linode's address
once that's known. The installer waits up to 30 minutes for the name to lead to the machine.

The script downloads the release, checks the installer against the hash fixed in the script, and runs it with
your answers. When it's done, the link for the first account appears above the login prompt in the Linode's
Lish console, and in `/var/log/compromise-checker-install.log`, which only root can read. The note on the console goes once the first
account exists. The question about SSH passwords is usually left for later on a new Linode: nobody has logged in
with a key yet, so the installer leaves passwords on and the page says how to turn them off.

This route isn't advertised until it has been tried by a few people outside NouriLoop.

## Updating

The web interface asks GitHub once a day, when someone with full access opens a page, for the public list of
this tool's releases, and downloads the newest one's signed description. Nothing about this machine or its
servers is sent, and the check can be turned off in Settings. When a newer version exists, every page says so
to people with full access, more loudly when the release is marked as a security fix. The check can't tell when
a newer release is being kept from it, so a security fix is also announced on nouriloop.com.

Manage → Updates installs it. A person with full access confirms with their password, and a code if two-factor
sign-in is on, and the tool's own account fetches the release and its dependencies, checks them against what
the release key signed, and leaves them in its folder with a request. A small root service,
`compromise-checker-update`, is started by that request and takes nothing from it: it copies the release into a
folder only root can write, checking every file against the signed description as it goes, refuses anything
not newer than the running version or signed by any other key, installs the new version beside the old one
from those files alone (it never contacts the network), and then moves the `current` link and restarts the web
interface. If the new version doesn't answer within a minute, the link goes back, the old version is
restarted, and the new one is removed. The previous version is kept on the machine, so a bad update can also
be undone by hand: point `/opt/compromise-checker/current` back at it and restart
`compromise-checker-web`. The outcome is on the Updates page and in `journalctl -u compromise-checker-update`.

On a machine without internet, copy a release's files over and run, as the tool's account:

    sudo runuser -u compromise-checker -- env CHECKER_HOME=/var/lib/compromise-checker/data \
        /opt/compromise-checker/current/bin/checker update --from /path/to/the/release

If that folder also holds a `wheels` folder with the dependencies, as `pip download --require-hashes
--only-binary :all: -r requirements.lock -d wheels` fetches them on a machine with internet and the same
Python, nothing is fetched; without one, the dependencies are fetched from PyPI. The same command without
`--from` fetches the newest release from GitHub, and `--check` only says what the newest version is. The daily check set from the Check every day page keeps working across updates: the web
service runs through `/opt/compromise-checker/current`, so what it starts follows the link.

## The setup link

    sudo /usr/local/sbin/compromise-checker-link

This makes a new link, and any link before it stops working. A restart of the machine or the web interface also
replaces the link, so use this command if yours stops working. Once there's an account, no link is needed.

## What it doesn't do yet

- It doesn't back up the evidence. [Backing up the evidence key](#backing-up-the-evidence-key) says what a lost
  machine means.
