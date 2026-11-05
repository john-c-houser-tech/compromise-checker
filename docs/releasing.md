# Releasing the tool (maintainers)

A release is a set of files on GitHub, signed by hand with the release key. No key is held by CI or any
server. The release key is kept offline and is apart from the keys that sign threat packs: a pack
teaches the tool what to look for, while a release replaces its code.

## What's in a release

| File | What it is |
| --- | --- |
| `checker-VERSION-py3-none-any.whl` | the tool |
| `requirements.lock` | every dependency: one exact version of each, with its hashes |
| `install.py` | the [installer](install.md), told which version it's for |
| `release.json` | the version, the commit, the date, whether it's a pre-release or a security fix, and each file's hash and size |
| `release.json.minisig` | the release key's signature of `release.json` |

Only `release.json` is signed, and every other file is trusted through its hash there.
`checker/releases.py` is what reads it.

Releases cover x86 machines for now. The dependency list has Arm's files too, but nothing has been run
on Arm.

## The dependency lists

`release/requirements.lock` is what machines install. `release/build-requirements.lock` pins the tool
that builds the wheel. A dependency only reaches machines through a new release of this tool, so a serious
hole in one of them means making a release.

    python scripts/release.py lock                    # move everything to its newest version
    python scripts/release.py lock --package django   # or only this one
    uvx pip-audit --require-hashes --disable-pip -r release/requirements.lock

Read what moved before committing it. This needs [uv](https://docs.astral.sh/uv/). Machines install with
`pip install --require-hashes --only-binary :all:`, so a dependency is never built from source on them.
That works on Python 3.12 to 3.14; on 3.15, PyYAML has no wheel yet.

## Version numbers

`__version__` in `checker/__init__.py` and `COLLECTOR_VERSION` in the collector have to agree, and be plain
`X.Y.Z`. There's no beta form of a version: whether a release is a pre-release is in its `release.json`. So
each version is published once, and a final release can't reuse the number of a pre-release: after a
pre-release of `0.1.0`, the next final is `0.1.1` or later.

## Making a release

From the newest commit on `main`, after the change that sets the version has been merged:

1. Refresh and audit the lists, as above, and merge any change first.
2. Tag the commit, and don't push the tag yet: `git switch main && git pull --ff-only && git tag vVERSION`.
3. Build it. Use `--final` instead of `--prerelease` for a final release, and add `--security-fix` for one
   that machines should be told to hurry with:

       python scripts/release.py build --prerelease

   It asks GitHub for the newest commit on `main`, and refuses unless that's this commit and the tag is too,
   so a release can't miss a fix that's already merged. The wheel comes from what's committed, never from the working
   folder. It's built twice, with the pinned build tool and none of your own settings, and refused if the
   two differ or its files aren't exactly what git has for this commit.
4. Restore the release key from its offline copy, somewhere that isn't this repository, such as
   `/run/user/$UID/`. Sign, and don't touch a file after this:

       minisign -S -s /run/user/$UID/release.key -m dist/release-VERSION/release.json -t "Compromise Checker VERSION"

5. Remove the key from this machine again.
6. Check it as a machine would, which also prints the command to publish it, naming each file. It refuses
   if the folder holds anything else, so a stray file can't get published. For a release that changes the key,
   add `--key` with the public key machines trust now:

       python scripts/release.py verify dist/release-VERSION

7. Push the tag, and publish it with that command: `git push origin vVERSION`.

`build --trial` is for checking the build: it writes to `dist/trial-VERSION/`, and no machine reads what it
makes, even if it's signed.

## Checking a release by rebuilding it

Check out the tag and rebuild with `python scripts/release.py build --prerelease --trial`, then compare the
wheel's hash with the one in `release.json`. The build fixes the dates and file permissions, and Python 3.12,
3.14 and 3.15 gave the same wheel when tried. The compression comes from the machine's
zlib, so a Python built with a different zlib could give a different hash from the same files. If so, compare
what's inside the wheels.

## What a signature doesn't do

It says the release key signed these files once. It doesn't say they're the newest:

- **An older release can be offered.** Someone who controls the download could offer an old, signed release
  with a known hole. An update refuses anything not newer than what's installed, and a first install names
  the exact version it wants. Both of those are checked by whoever calls `checker/releases.py`.
- **A newer release can be withheld.** A machine can't tell from a signature that it isn't being shown one. It
  can only show how old the newest release it can see is. So a security fix also needs announcing.

Installed machines find releases through GitHub's list of them (`checker/updates.py`), by tag `vVERSION`, and
trust only the signed `release.json` published with each. `--security-fix` is what makes their notice loud, and
`--prerelease` keeps a release from machines on a final version.

## Making the key

    minisign -G -p release.pub -s release.key -c "Compromise Checker release key"

Use a password of its own. Keep the secret key and its password offline, in more than one place, and never
leave it on the machine that builds: it's only there for the moment of signing. The public key goes in `RELEASE_KEYS` in `checker/releases.py`, in the install
script, and on nouriloop.com. A real build refuses if `RELEASE_KEYS` is empty.

## If the release key is lost or stolen

Machines trust the keys in the version they already run (`RELEASE_KEYS` in `checker/releases.py`). A release
signed with one of those can change the list, and so can whoever holds a stolen key.

- **Lost:** no new release can be signed that an installed machine would accept, so each one has to be
  installed again with a version carrying a new key.
- **Stolen:**
  1. Say so publicly at once, by every route you have. A machine can't be told any other way.
  2. Publish a release carrying a new key and dropping the old one, signed with the old key. Check it with
     `verify --key` and the old public key. Machines that take it stop trusting the stolen key.
  3. Put the new key in the install script, the pasted line and the Linode form, so new installs don't trust
     the old one, and on nouriloop.com.
  4. Each key-changing release is a step machines have to take: one that skips it can't check anything signed
     with the new key.
  5. **A machine that took a release made by the thief has run their code as root, with admin keys to every
     server it checks.** It can't be cleaned or trusted. It has to be rebuilt, its evidence key treated as
     known to them, and its login key removed from every server and replaced. Those servers then need
     checking, from the rebuilt machine, as possibly broken into.
