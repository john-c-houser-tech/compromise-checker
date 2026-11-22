# Checking Ubuntu Pro (ESM) packages (2026-11-22)

Issue #217, the last item: decision 5 of the PAM plan (`pam-offserver-verify-plan-2026-11-21.md`).
Draft 1. The open decisions are at the end of this plan; nothing is built until John has settled
them and step E.1 has answered what public sources don't.

## The problem

Servers attached to Ubuntu Pro get some updates from ESM (Expanded Security Maintenance) instead of
Ubuntu's public archive. Those packages are on `esm.ubuntu.com`, behind a token, and signed with
their own keys. Since #189, the checker matches changed PAM modules against the distribution's own
signed packages. An ESM version can't be fetched, so today it is reported as "an Ubuntu Pro (ESM)
version: ESM packages need a Pro token to download, so the checker can't check them yet" and the
finding stays high (`deb.py`, from the `+esm` in the version, without searching).

That is rare now, and it gets common soon:

- **Ubuntu 22.04 after its standard support ends (April 2027).** From then on, fixes to `main`
  packages, `libpam-modules` among them, come only through **esm-infra**. A 22.04 server attached
  to Pro that takes a PAM update would raise a high finding the checker can't clear, every time.
- **Universe PAM modules on any LTS** (`libpam-google-authenticator`, `libpam-yubico` and the like)
  get their security fixes through **esm-apps** whenever the server is attached to Pro.

A server that isn't attached to Pro never gets `+esm` versions, so nothing changes for it.

## What ESM is, from public sources

Confirmed by more than one source, or by the Pro client's own code (sources at the end):

- **Two repositories:** `https://esm.ubuntu.com/infra/ubuntu/` (esm-infra) and
  `https://esm.ubuntu.com/apps/ubuntu/` (esm-apps). Suites are `<codename>-infra-security` and
  `<codename>-infra-updates`, and `<codename>-apps-security` and `<codename>-apps-updates`,
  component `main`, laid out like the archive (`dists/…/main/binary-amd64/Packages…`, `pool/…`).
- **apt authenticates with HTTP basic auth:** `/etc/apt/auth.conf.d/90ubuntu-advantage` holds one
  line per repository, `machine esm.ubuntu.com/infra/ubuntu/ login bearer password <token>`.
- **Signing keys:** their own, shipped by the Pro client as `ubuntu-pro-esm-infra.gpg` and
  `ubuntu-pro-esm-apps.gpg`. Fingerprints aren't in the sources read so far.
- **Getting a token:** an organization (or a person, on the free personal subscription) has a
  **contract token** from the Ubuntu Pro dashboard. `pro attach` sends it to the contract server
  (`contracts.canonical.com`, `/v1/context/machines/token`, `Authorization: Bearer <contract
  token>`, with a machine ID, architecture and OS details). The answer has a **machine token** and
  **resource tokens**, one per service. The Pro client refreshes the machine token through
  `/v1/contracts/{contract}/context/machines/{machine}` and gets a service's resource token through
  `/v1/resources/{resource}/context/machines/{machine}`.
- **Attaching registers a machine** against the subscription. The free personal subscription
  covers 5 machines (a third-party source; to be confirmed against Canonical's own terms).

**Not known yet, for E.1 to answer:**

1. Whether `InRelease` and the `Packages` lists need the token, or only the `pool/` files.
2. Which token goes in apt's password (resource token, by the Pro client's code), how long it lasts,
   and what renews it.
3. The ESM signing keys' fingerprints, which key signs which suite, and whether 26.04 has ESM
   suites yet.
4. Whether every ESM version carries `+esm` (the checker's trigger today).
5. Whether attaching and then detaching a machine frees its seat again.
6. **Whether Canonical's terms allow it**: one attached machine (the checker's) downloading ESM
   packages to check files on other attached machines, without installing them (decision 2).

## The idea

The same check as #189, with ESM as one more signed source. When a server claims an `+esm` version
of the package that owns a changed PAM module, the checker's machine looks it up in the ESM lists
for that release (`-infra-security`, `-infra-updates`, `-apps-security`, `-apps-updates`). It checks
the `InRelease` signature with the ESM keys pinned in the checker, then the list's hash, then the
`.deb`'s hash, and compares the module's SHA-256 by path. The rules for a match, a mismatch, an
owner change and being held to the baseline all stay as #189 built them (V.4–V.7, #223–#226).

Nothing about trust changes. The token only opens the door: the evidence is still the signature
chain, from keys in the checker, never from the server.

## Getting access: the options

The servers' own tokens are never used. They are on the servers, root can read and change them,
and collecting them would send a secret off every server. So the checker needs access of its own.

**A. The checker attaches itself through the contract server (recommended, pending E.1 and
decision 2).** The administrator gives the checker the organization's contract token, held like the
advisor's API key (env, keyring or a command; never in `config.yaml`). A new command,
`checker pro attach`, registers the checker's machine once (one seat), stores the machine token in
an owner-only file under `CHECKER_HOME`, and gets resource tokens when a run needs them.
`checker pro detach` gives the seat back.
- Works on every checker machine (Ubuntu or Rocky), with no Pro client installed.
- Uses the contract server's API, which isn't a published interface (the Pro client is its only
  documented user). If it changes, ESM versions go back to "can't be checked yet", with a reason.
  No finding gets quieter.

**B. The administrator pastes resource tokens.** They copy them from an attached Ubuntu machine's
`auth.conf.d` file into the checker's settings.
- Simplest to build. But the tokens rotate, so ESM checks would stop silently until someone copies
  them again. Nobody would notice.

**C. The checker's machine itself runs `pro attach`.** The checker reads the root-only
`auth.conf.d` file, through a narrow sudo rule.
- Uses the supported client. But it only works on Ubuntu checker machines, and it gives the checker
  a root path it doesn't have today.

**D. No token: the server's downloaded `.deb`.** apt keeps the `.deb`s it installed in
`/var/cache/apt/archives` until they're cleaned. If the signed lists turn out to be public (E.1, item
1), a `.deb` collected from the server could be checked against them by size and SHA-256.
- No token and no seat. But automatic updates clean that cache, so it would usually be gone. It
  would also mean sending megabytes off each server. **Not recommended**, though E.1 records whether
  it's possible.

## Where the secrets live

- **Contract token:** like the advisor's key: `verify.ubuntu_pro_token_source` (env, keyring, or
  `command:<command>`), read only when attaching, kept in memory only for that command.
- **Machine token:** an owner-only file, `CHECKER_HOME/secrets/ubuntu-pro.json` (`0600`, in a
  `0700` folder, `O_NOFOLLOW`). Never in evidence, reports, logs or error messages.
- **Resource tokens:** in memory, for one run.
- **Sent only to** `contracts.canonical.com` (the contract token and the machine token) and
  `esm.ubuntu.com` (the resource tokens), over HTTPS only.
- **Redirects:** urllib copies a request's ordinary headers onto a redirect (checked in Python
  3.12's `redirect_request`), so a token sent that way could follow one. Two guards: the fetcher
  already refuses redirects to another host and from https to http (`_SameHost`), and the token is
  added with `add_unredirected_header`, which urllib never copies onto a redirect. It is added only
  for `esm.ubuntu.com` addresses. A test proves a redirect never sees it.

## What the check reports

- **With access, an `+esm` version** is checked like any other: matched → the low
  `official_update`, differs → high, the rest as #189.
- **Without access** (no token, not attached, or access lapsed): as today, still high, with one
  coverage note per host: "N PAM modules come from Ubuntu Pro (ESM) packages; attach the checker
  to Ubuntu Pro to check them (`checker pro attach`)". A lapse says which (the contract server
  refused, the token expired).
- **The contract server unreachable** works like the archive unreachable: transient, asked again
  next run, and under the run's clock (#232, #233).
- **Older ESM versions:** there are no dated copies of ESM (snapshot.ubuntu.com covers only the
  public archive). A version that's no longer in the current ESM lists is "not checked: no longer
  in Ubuntu Pro's lists", as for other old versions without dated copies.

## Network, privacy and cost

- **New hosts the checker machine reaches:** `contracts.canonical.com` (attach, refresh, resource
  tokens) and `esm.ubuntu.com` (lists and packages). Only once attached.
- **What leaves the machine, and who learns it:**
  - Requests to the public archive are anonymous.
  - **ESM requests carry the organization's token,** so Canonical can tie "this subscription
    fetched `libpam-modules <version>+esm<n>` for 22.04" to the account. Still no server
    names, addresses or findings.
  - Attaching sends the contract server the checker machine's details (a random machine ID,
    architecture, OS release, kernel), as `pro attach` does.
  - Policy §10 and the install page's outgoing list say all of this.
- **Cost:** one seat on the organization's subscription. For our own testing, the free personal
  subscription (5 machines).
- **Caching:** ESM lists and results go in the same caches as the archive's, under the same rules:
  kept by hash, re-checked on every use, pruned after 30 days unused (#231).

## Open decisions

1. **Access route.** A, B or C above. **Recommended: A**, if E.1 shows the contract server's
   answers are stable enough to build on. If not, B, with a coverage note whenever the tokens stop
   working.
2. **Terms.** Before anything ships: does Canonical's Ubuntu Pro service description and terms
   allow an attached checker machine to download ESM packages to check files on other attached
   machines, without installing them? John reads the current terms, and asks Canonical if they
   aren't clear. If it isn't allowed, ESM stays "can't be checked", and the docs say why.
3. **Off unless attached.** No contract token means no ESM requests at all, and today's behaviour.
   **Recommended: yes.** Attaching is a deliberate step, since it uses a seat and names the
   organization to Canonical.
4. **Which services.** **Recommended: esm-infra and esm-apps both**, since PAM modules come from
   `main` and `universe`. FIPS, CIS and the other Pro services aren't covered (FIPS PAM modules are
   rebuilt packages with their own lists and keys); their versions keep a reason saying so.
5. **A Pro token for testing.** E.1 and E.5 need a free personal Ubuntu Pro subscription, used
   on the laptop and on a Linode. John gets the token, and runs the steps that start Linodes or
   attach machines.

## Steps (one pull request each, after the decisions)

- **E.1 Prove it by hand** (John runs the parts that attach or start Linodes; no product code).
  Attach a throwaway machine ID from the laptop through the contract server and record the
  answer's shape, with tokens redacted. Fetch an ESM `InRelease` with and without the token (item
  1). Get the ESM key fingerprints from the Pro client's keyrings. Verify a `jammy-infra-security`
  `InRelease` → `Packages` → `.deb` chain, and one from `-apps-`. Check whether 26.04 has ESM suites
  and whether every version there has `+esm`. Detach, and check the seat count. Results go in this
  plan, like V.1.
- **E.2 Access:** `verify.ubuntu_pro_token_source`, `checker pro attach | detach | status`, the
  owner-only machine-token file, refreshing, resource tokens per run. Tests against a recorded,
  redacted contract-server answer. A test that no token ever appears in evidence, reports, logs or
  errors.
- **E.3 The ESM lists in the verifier:** the ESM keys pinned, the ESM suites as places in
  `deb.Ubuntu` for `+esm` versions, the `Authorization` header only for `esm.ubuntu.com`, with a
  redirect test. Signed lists kept and pruned like the archive's. Under the run's clock.
- **E.4 Report and docs:** the coverage note without access, the lapse reasons, `docs/checks.md`,
  `docs/install.md` (outgoing hosts, `checker pro attach`), policy §10 (the token and what Canonical
  learns) and policy's secrets section. John reads the policy wording.
- **E.5 The proof on a real server** (John runs it): a 22.04 Linode attached to the personal
  subscription, `pam_update_proof.py` extended for an ESM update. Expect one low `official_update`;
  a swapped module stays high. The Linodes are detached and deleted afterwards.

## Sources

- Canonical's Pro client source, `uaclient/contract.py` (attach, refresh and resource-token
  endpoints): https://github.com/canonical/ubuntu-pro-client
- "About ESM, esm-apps and esm-infra", Pro client docs:
  https://documentation.ubuntu.com/pro-client/en/v30/explanations/about_esm
- "How to get an Ubuntu Pro token and attach to a subscription":
  https://documentation.ubuntu.com/pro-client/en/v31.2/howtoguides/get_token_and_attach
- "Mirror Ubuntu Pro packages without Landscape" (third-party, April 2024; repository URLs, suites,
  `auth.conf` format, key file names, the free subscription's 5 machines):
  https://cstan.io/en/post/2024/04/ubuntu-pro-mirror/
- `apt_auth.conf(5)`: https://manpages.ubuntu.com/manpages/resolute/man5/apt_auth.conf.5.html
