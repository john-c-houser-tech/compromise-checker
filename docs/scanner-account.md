# Setting up a scanner account

The recommended way to let Compromise Checker into a server: a dedicated
account that can log in only with one key, only from the controller, can run
only one command, and can use sudo only for that command.

## What this account can do — read this first

The sudo rule below lets the account run the system Python interpreter as
root, with a program it supplies. **That is equivalent to full root access.**
It has to be: the collector reads files only root can read, such as the
authentication log.

What limits the risk:

- when the tool runs, the program is the published collector, and its
  SHA-256 fingerprint is stored with every collection, so you can check what
  the tool ran;
- the key works only from the controller's address, and can't open a shell,
  forward ports or run any other command (the `authorized_keys` options
  below);
- every use is logged by sshd and sudo, and the tool never removes those
  records.

What does **not** limit it: none of this restricts *what Python* the root
interpreter runs. Whoever holds the controller's key, connecting from the
controller's address, can run any code as root on every server set up this
way. The protection is keeping that key and that machine safe.

Your security team should know about the account and decide. Treat the
controller and its key as root credentials for the servers it checks.

## On each server (as an administrator)

Replace `203.0.113.10` with the controller's address and the key with the
controller's public key.

```sh
# 1. The account: no password, so it can only log in with the key.
sudo useradd --create-home --shell /bin/sh --comment "Compromise Checker" scanner
sudo passwd -l scanner

# 2. Its key, locked to the controller's address and to one command.
sudo install -d -m 700 -o scanner -g scanner /home/scanner/.ssh
echo 'restrict,from="203.0.113.10",command="sudo -n -- python3 -I -B -" ssh-ed25519 AAAA... checker@controller' \
  | sudo tee /home/scanner/.ssh/authorized_keys > /dev/null
sudo chown scanner:scanner /home/scanner/.ssh/authorized_keys
sudo chmod 600 /home/scanner/.ssh/authorized_keys

# 3. The sudo rule: exactly this interpreter with exactly these arguments.
echo 'scanner ALL=(root) NOPASSWD: /usr/bin/python3 -I -B -' \
  | sudo tee /etc/sudoers.d/compromise-checker > /dev/null
sudo chmod 440 /etc/sudoers.d/compromise-checker
sudo visudo -cf /etc/sudoers.d/compromise-checker
```

What the `authorized_keys` options do:

- `restrict` — no terminal, no port, agent or X11 forwarding.
- `from="…"` — the key works only from the controller's address.
- `command="…"` — whatever the client asks for, this is what runs. It is
  exactly the command the tool sends in its `nopasswd` sudo mode, so the key
  can't open a shell or run any other command. **It does not limit the
  program:** that interpreter runs as root whatever Python it is given on
  its input. Anyone holding this key, from the allowed address, can run any
  code as root. Protect it like a root credential.

`python3` is `/usr/bin/python3` on RHEL 9 and 10, Rocky, AlmaLinux and
Ubuntu 22.04 and later. If `visudo` reports a problem, fix it before logging
out: a broken sudoers file can lock administrators out of sudo.

## On the controller

```sh
checker hosts add web01 --address web01.example.org --user scanner --auth agent --sudo nopasswd
checker trust web01          # compare the fingerprint with the server's own:
                             #   ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Use `--auth key --key PATH` instead of `--auth agent` to name a key file.

## Other set-ups

- **Logging in as root** (`--sudo root`): works, but most organisations
  forbid direct root login over SSH, and it gives up the separate audit trail.
- **sudo with a password** (`--sudo password`): for accounts without a
  `NOPASSWD` rule, typically administrators with a general sudo rule. The
  tool waits for sudo's own prompt before sending the password, so a password
  is never sent unless sudo asks for it. Python then starts with a one-line
  bootstrap (`python3 -I -B -c '…'`) that announces itself before reading the
  collector, and the collector is sent only after that announcement — proof
  that sudo accepted the password. The account's sudo rule must therefore
  allow `python3` with those arguments, and the forced `command=` option
  above can't be used in this mode.
- **Password SSH login** (`--auth password`): supported, not recommended.

## Removing access

```sh
sudo rm /etc/sudoers.d/compromise-checker
sudo userdel --remove scanner
```
