# Installing

Compromise Checker needs a machine of its own: it holds keys that act as an administrator on every server it
checks. It installs on x86 machines running Ubuntu 24.04 or 26.04, or Rocky Linux 9 or 10. Close relatives of
those, such as Linux Mint, aren't supported yet, and the installer stops with a message.

This covers using the tool from the machine it's on, with a browser there. Reaching it from other computers
isn't built yet.

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

## The setup link

    sudo /usr/local/sbin/compromise-checker-link

This makes a new link, and any link before it stops working. A restart of the machine or the web interface also
replaces the link, so use this command if yours stops working. Once there's an account, no link is needed.

## What it doesn't do yet

- It doesn't back up the evidence. If the machine is lost, so is each server's history, and the tool starts again
  from what each server looks like that day.
