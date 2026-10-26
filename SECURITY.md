# Security

## Reporting a vulnerability

Email **security@nouriloop.com**. Please include:

- what you found and where (file, command, or part of the collection
  process);
- steps to reproduce, and the version or commit you tested;
- what an attacker could do with it.

Please do not open a public issue for a vulnerability.

## What to expect

NouriLoop LLC is a small company, so these are commitments we can keep:

- acknowledgement within **3 business days**;
- an initial assessment within **10 business days**;
- a fix, or a published mitigation, within **90 days** for confirmed issues,
  sooner for serious ones, with a date for public disclosure agreed with you;
- credit in the release notes, if you want it.

## Scope

In scope:

- the collector (`checker/collector/collector.py`), especially anything that
  could make it write to, change, or harm a server it checks;
- the controller: SSH handling, host-key checking, credential handling,
  evidence encryption and integrity;
- threat-pack signing and verification;
- the AI advisor's handling of untrusted log text.

Out of scope: weaknesses in the servers you check with the tool. Report those
to whoever runs them.

## Good-faith research

We will not take legal action against research done in good faith that
follows this policy: it stays on systems you own or are authorized to test,
avoids harm to others' data and services, and gives us a reasonable chance to
fix the problem before it is made public.

## Supported versions

Nothing has been released yet. Once releases begin, security fixes go into
the latest release.

See also [the security and privacy policy](docs/security-and-privacy-policy.md).
