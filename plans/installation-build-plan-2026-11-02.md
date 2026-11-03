# Installation build plan — 2026-11-02

> **Status: DRAFT 1, 2026-11-02.** All decisions (I1 to I11) settled. Nothing is built yet.

**Goal:** someone at a small organization who doesn't use a command line can get Compromise Checker
running on a machine of their own and reach its first-setup page in a browser.

**Done means:**
1. **Pasted command.** On a new Ubuntu or Rocky machine, one pasted line checks the signature, installs the
   tool and hands over a working first-setup link, on both ways of reaching the page.
2. **Linode form.** The same result with no terminal, the link read from the provider's browser console.
3. **Locked down.** The automatic changes are made and reported, each permission question works, and nobody
   can be locked out by them. Proved with SELinux enforcing on a real Rocky Linode.
4. **Updates.** The button installs a newer signed release, refuses anything else, and a failed update rolls
   back by itself. Both are proved on a real machine.
5. **Backed up as far as promised.** The evidence key can be copied from the page, and the page says plainly
   what a lost machine means.
6. **Released.** `0.1.0` is published as a signed pre-release, labelled a beta.

## Decisions

- **I1. The main way to install. DECIDED (John, 2026-11-02):** a signed install script for a dedicated
  Linux machine (Ubuntu or Rocky) first. A one-click cloud server is built on top of it, by running the
  same script on a new machine. Docker Compose may follow, and perhaps a desktop installer: both deferred.
- **SELinux (John, 2026-11-02):** tested on a Rocky Linode as this work needs it.
- **I2. What the script installs. DECIDED (John, 2026-11-02):** signed GitHub Releases: the tool plus an
  exact list of every dependency with its hash. Signed by hand with minisign, using an offline release
  key separate from the pack key. The script stops unless the signature checks out.
- **I3. How an installed machine updates. DECIDED (John, 2026-11-02):** an update button in the web
  interface. A person with full access confirms with their password and code, and the action goes in the
  activity record. A small separate service with root rights then installs the update. It can only install
  a newer release with a valid signature, and takes no other instructions from the page. The previous
  version is kept, so a failed update rolls back by itself. The notice gets more prominent when a release
  is marked as a security fix. Checking for a new version contacts GitHub, so the policy says so and it can
  be turned off. Automatic updates may come later as an opt-in, once several releases have gone smoothly.
- **I4. How the team reaches the page. DECIDED (John, 2026-11-02):** the organization's own web address,
  with an automatic certificate. The person adds one DNS record and gives the script the name. The script
  sets up Caddy, using the proxy route the tool already supports. An optional step limits https to the
  addresses the person names, such as the office. Port 80 stays open so the certificate can renew. A
  local-network route or a private network service such as Tailscale may follow if people ask.
- **I5. How the install gets started. DECIDED (John, 2026-11-02):** two routes in the first release. One
  command pasted into a terminal, which downloads the script, checks its signature and runs it, for any
  machine. And Linode's setup form, which runs the same steps with no terminal; how to publish it gets
  confirmed before building. The form never asks for anything secret. Pasted "user data" and other
  providers may follow if people ask.
- **Required:** the DNS record can only be added once the machine's address is known, so the certificate
  step keeps retrying until the name works.
- **I4 changed: two ways to reach the page (John, 2026-11-02).** A PC behind a router normally can't get
  a certificate from Let's Encrypt, so the script asks first: "Will people use this from other computers?"
  - **No, only from this PC:** no web address, DNS record or Caddy. The page stays on this machine only,
    which is already the tool's default.
  - **Yes:** the web address route above. The script first checks the machine can be reached from the
    internet. If it can't, it says so plainly and suggests a cloud server, instead of retrying forever.
    (The retrying above covers a DNS record not added yet.)
  - Sharing a local PC with a team isn't in the first release. Tailscale is the first thing to add if
    people ask for that.
- **I6. How the first-setup link reaches the person. DECIDED (John, 2026-11-02):** with the pasted command,
  in the terminal, plus one short command to show it again, which asks for the computer's password. With
  the Linode form, on the provider's browser console, above the login prompt, with no login or typing,
  and removed once used. If a real Linode test shows the link can't be copied from that console, it
  becomes a short code to type, with a limit on wrong tries.
- **Required on a local PC:**
  - The script stops with a clear message on anything but Ubuntu or Rocky.
  - The install turns sleep off or warns about it, and the page shows when a check was missed.
  - Server setup commands include this machine's address, and home and small office addresses can change.
    Find out how the commands use it and make sure a change can't lock the tool out.
  - The machine is still used only for this.
- **I7. Locking down the machine. DECIDED (John, 2026-11-02):**
  - **Done automatically, and the person is told as each one is done:** automatic operating system security
    updates, and a firewall allowing only SSH and, on the web address route, ports 80 and 443.
  - **Each one only with the person's permission, asked separately:** turning off SSH passwords, turning off
    root login over SSH, and automatic blocking of repeated login failures. The script asks in the terminal.
    The Linode form has a yes or no for each, set to no.
  - **Safety checks:** SSH passwords stay on unless a working key login exists, and root login stays on
    unless another administrator account has one. Otherwise the script says why it left that setting alone.
    If SSH isn't already running on a local PC, the script doesn't turn it on and these questions don't apply.
  - **Notices on the web page:** while SSH still accepts passwords, and when a kernel update needs a
    restart. The machine never restarts by itself.
- **I8. Backing up the evidence key. DECIDED (John, 2026-11-02):** a person with full access confirms with
  their password and code, and the one line of the key appears with a button to copy it, for pasting into a
  password manager. The action goes in the activity record, and it can be shown again the same way. First
  setup points to it directly, on both install routes, and still says the file can be copied by anyone who
  prefers that. It's never offered as a file to download. The policy wording changes and goes to John
  for approval.
- **I9. Backing up the evidence itself. DECIDED (John, 2026-11-02):** not in the first release, and the tool
  says so plainly. The page and the docs state what a lost machine means: the history goes, and the tool
  starts again from what each server looks like that day. They also explain the choice of turning on the
  provider's machine backups, including that those hold the keys and evidence together. A built-in daily
  backup to storage the organization chooses may follow if people ask. It gets its own plan, because
  purged evidence staying in a backup conflicts with the retention promises.
- **I10. A machine already in use. DECIDED (John, 2026-11-02):** before changing anything, the script looks
  for other programs accepting connections and other people's login accounts. It lists what it found, says
  why each matters and what could break, and stops unless the person types a short sentence to go ahead. If
  the web address route is chosen and something else is using port 80 or 443, it stops with no way past. The
  Linode form skips this check, because it always starts on a new machine.
- **I11. How the first release is offered. DECIDED (John, 2026-11-02):** a public beta: version `0.1.0`,
  marked as a pre-release on GitHub. The install page says it's a beta, what hasn't been tried, and that it
  has had no outside security review. The Linode form exists but isn't advertised until John has installed
  through both routes and a few outside people have tried it. The update check ignores pre-releases on a
  machine running a final version.
- **Machines (2026-11-02):** x86 only in the first release, since that's what the real-machine tests can
  run on. The dependency list has Arm's files too, so adding Arm later is a matter of testing it.
- **The version number (2026-11-02):** stays `0.1.0.dev0` until I.8 sets `0.1.0`. A version has no beta form,
  so the first final release after the `0.1.0` pre-release has to be `0.1.1` or later.
- **Python (2026-11-02):** 3.12 to 3.14 in the first release, always installed with `--only-binary`, so a
  dependency is never built from source as root. 3.15 waits for a PyYAML wheel.
- **Default database:** the tool's ordinary file on the machine. PostgreSQL stays available through
  `checker store move` for anyone who wants it. The script doesn't install it.

## Ground rules

- Each PR goes to dev, with an agent review first, then Copilot. John alone merges dev to main.
- Policy wording goes to John before it's committed. I.3, I.4, I.5 and I.6 each change what the policy says.
- Real-machine tests need John's OK once per PR, within a $10 cap, and he gets a warning before any
  1Password prompt.
- The release key is made by John and stays offline. It's never read or used by anything but him. Only its
  public half goes in the script and the repo.
- The script never asks for a secret on a command line or stores one in the Linode form.

## Pull requests

- **I.1 Release build.** Make the exact list of dependencies with their hashes, write the
  steps for building and signing a release, and put the public release key in place. John makes the key.
- **I.2 Install script, this PC only.** The pasted line, the signature check, the Ubuntu or Rocky check, the
  check for a machine already in use, the tool's own account, the services (so daily checks run with nobody
  logged in), the first-setup link and the command to show it again. Sleep turned off or warned about, and
  a missed check shown on the page. The Pango libraries that PDF reports need. **Nothing from the release
  runs before its signature is checked,** and `checker/releases.py` can't do that on a new machine, since it
  needs dependencies from the release being checked. So the script is one file using only what comes with
  Python, with its own short Ed25519 check, tested against the tool's and against real minisign. Rocky doesn't
  package `minisign` in its base sources. The script also names the exact version it expects, so an older signed
  release can't be given to a new install. Installing on Ubuntu 24.04 and 26.04, and Rocky 9 and 10.
- **I.3 The web address route.** The question at the start, the check that the machine can be reached,
  Caddy with the proxy secret, retrying until DNS works, the stop if port 80 or 443 is taken, and the
  optional address limit.
- **I.4 Lockdown.** Check that the firewall really closes what a new system leaves open (Linode's Rocky 10 has
  `rpcbind` on port 111 and Cockpit's socket on port 9090). The automatic changes and how they're reported, the three permission questions and their
  safety checks, and the notices on the page. The SELinux test on a Rocky Linode goes here, and the
  policy wording for what the script changes.
- **I.5 Keys and lost machines.** The evidence key on the page, first setup pointing to it, the statement
  about a lost machine, and the policy wording. When a person adds a server from a machine on the "only
  from this PC" route, the page warns that limiting it to this machine's address can lock the tool out if
  that address changes. (Today that limit is optional, and the person types the address.)
- **I.6 Updates.** The version check and its off switch, the notice and its louder form for security fixes,
  the rule on pre-releases, the button, the root service, keeping the previous version and rolling back.
  The daily timer names the Python of the version that set it, so an update has to set the timer again, or the
  old version keeps running the checks.
  The service installs only from `stage_release`'s private copy, with `newer_than` set, and keeps the
  installed release's manifest, since that's the only record of whether a machine is on a pre-release.
  This is the new path from a web session to root, so it gets the closest review. Policy wording too.
- **I.7 Linode form.** Confirm how a form is published today, then build it, with the link above the console's
  login prompt. Test whether the link can be copied from there, and use a short code if it can't.
- **I.8 First release.** The whole path on real machines, on both distributions and both routes, including a
  real download, which proofs before this replace with a local folder. Then the install page, with the pasted
  line that `release.py verify` prints. That line holds the installer's hash, which is all that protects the
  installer, so the page has to live apart from the release's own files. John signs and publishes `0.1.0`.

## Not known yet

- A newer release being withheld from a machine can't be detected from a signature alone. The signed
  `published` date lets the page show how old the newest release it can see is. Settled in I.6.
- Where Caddy and the login-failure blocker come from on each distribution, and how far each source can be
  pinned the way the tool's own dependencies are. Settled in I.3 and I.4.
- The smallest machine that works, measured during I.8 so the install page can state it.
