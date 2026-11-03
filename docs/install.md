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
2. **Looks for other use.** Programs that other computers can reach, and other people's login accounts, are
   listed with why they matter. It stops unless you type a short sentence to go ahead. This is a nudge rather
   than a guarantee: it can't see everything. Nothing has been changed up to this point. If something else is
   using port 8088, it stops with no way past.
3. **Installs what's needed** from the system's own packages: a Python the tool can run on, and the libraries
   PDF reports use.
4. **Makes an account** called `compromise-checker`, which nobody can log in to, with a private folder at
   `/var/lib/compromise-checker`. If an account by that name already exists and doesn't look like one the
   installer made, it stops, rather than hand that account the tool's keys.
5. **Installs the tool** in `/opt/compromise-checker`, with exactly the dependency versions the release lists.
   Each is checked against its hash, and none is built from source. The tool's account can't change these files.
6. **Starts the web interface** as a service, as that account, answering only on this machine. It starts again
   after a reboot. That account's own systemd stays running, for the daily check.
7. **Turns sleep off,** so a daily check isn't missed. If the machine was off when a check was due, it runs when
   the machine next starts, and the page says when a server hasn't been checked for a few days.
8. **Gives you a link** for creating the first account. It works once, within an hour.

If it stops part way, run it again to carry on, whether or not an account has been made in the meantime. Once
it has finished, running it again changes nothing.

## A web address

For people to use it from other computers, the tool needs a name of its own, such as `checker.example.org`, and
the machine has to be reachable from the internet: a cloud server, typically. A PC behind a home or office
router can't get a certificate, and the installer says so rather than trying.

You'll be asked for the name, and whether only some addresses, such as your office's, may reach the page.
Before changing anything, the installer checks that the name leads to this machine. Some cloud providers
give a machine only a private address and pass a public one on to it, so if the name leads elsewhere, the
installer asks for a page by the name and sees whether the request arrives here. If the name doesn't exist yet, it shows the DNS record to add and waits for it. If it leads
somewhere else, it stops.

It then sets up Apache, from the system's own packages, in front of the tool:

- Apache gets a certificate from Let's Encrypt for the name, with its own `mod_md` module, and renews it. A daily
  reload lets Apache use a renewed certificate. Let's Encrypt checks that the name leads to this machine, and
  the name appears in public certificate logs. The account it makes there gives `webmaster@` and the name as
  its contact, since `mod_md` needs one, so nothing personal is sent.
- It answers on port 443, and port 80 only sends people to 443 and lets Let's Encrypt check the name. HTTP/2 is
  off. If a firewall is running, ports 80 and 443 are opened in it.
- The tool still listens only on this machine. Apache passes requests to it with a secret only they share, so
  nothing else on the machine can pass for Apache.
- On Rocky, SELinux keeps Apache confined. The narrowest switch that lets it connect out at all is turned
  on: `httpd_graceful_shutdown`, which, despite its name, only lets it reach web ports, Let's Encrypt's
  included. The tool's port is added to those.
- Apache keeps no access log for the name, since a setup link would be in it, and only passes on requests
  for the name itself.
- With a limit, only those addresses get past Apache to the page. Let's Encrypt can still reach port 80, so
  renewals keep working.

If Let's Encrypt can't reach the machine, the installer says so at the end, and Apache keeps trying. The page
doesn't work until it succeeds, and Apache starts using the certificate as soon as it arrives. The usual cause
is a firewall at the hosting provider that blocks port 80 or 443.

An installed machine can't be switched between the two yet. If an install with a web address stops part way and
is run again with the other answer, the installer takes down what it had set up for the web address.

Without a terminal to ask in, `--web-address NAME` and `--allow "ADDRESSES"` give the answers instead.

## The setup link

    sudo /usr/local/sbin/compromise-checker-link

This makes a new link, and any link before it stops working. A restart of the machine or the web interface also
replaces the link, so use this command if yours stops working. Once there's an account, no link is needed.

## What it doesn't do yet

- It doesn't back up the evidence. If the machine is lost, so is each server's history, and the tool starts again
  from what each server looks like that day.
