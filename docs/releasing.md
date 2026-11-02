# Releasing the tool (maintainers)

A release is a set of files on GitHub, signed by hand with the release key. No key is held by CI or any
server. The release key is kept offline and is apart from the keys that sign threat packs: a pack
teaches the tool what to look for, while a release replaces its code.

## What's in a release

| File | What it is |
| --- | --- |
| `checker-VERSION-py3-none-any.whl` | the tool |
| `requirements.lock` | every dependency: one exact version of each, with its hashes |
| `release.json` | the version, the commit, whether it's a pre-release or a security fix, and each file's hash and size |
| `release.json.minisig` | the release key's signature of `release.json` |

Only `release.json` is signed, and every other file is trusted through its hash there.
`checker/releases.py` is what reads it.

Releases cover x86 machines for now. The dependency list has Arm's files too, but nothing has been run
on Arm.

## The dependency lists

`release/requirements.lock` is what machines install. `release/build-requirements.lock` pins the tool
that builds the wheel. A dependency only reaches machines through a new release of this tool, so a serious
hole in one of them means making a release.

    python scripts/release.py lock
    uvx pip-audit --require-hashes --disable-pip -r release/requirements.lock

Read what moved before committing it. This needs [uv](https://docs.astral.sh/uv/).

## Making a release

From `main`, after the change that sets the version has been merged, with `__version__` in
`checker/__init__.py` and `COLLECTOR_VERSION` in the collector agreeing:

1. Refresh and audit the lists, as above, and merge any change first.
2. Tag the commit: `git tag vVERSION && git push origin vVERSION`.
3. Build it. Use `--final` instead of `--prerelease` for a final release, and add `--security-fix` for one
   that machines should be told to hurry with:

       python scripts/release.py build --prerelease

   This takes the wheel from what's committed, never from the working folder. It builds twice with the
   pinned build tool, and refuses if the two differ.
4. Restore the release key from its offline copy and sign. Don't touch a file after this:

       minisign -S -s release.key -m dist/release-VERSION/release.json -t "Compromise Checker VERSION"

5. Remove the key from this machine again.
6. Check it as a machine would:

       python scripts/release.py verify dist/release-VERSION

7. Publish it, leaving out `--prerelease` for a final release:

       gh release create vVERSION --verify-tag --prerelease --title "VERSION" dist/release-VERSION/*

Anyone can check a release by rebuilding the tagged commit with the same version of Python and comparing
the wheel's hash. The build date comes from the commit, so it doesn't change the result.

## If the release key is lost or stolen

Machines trust the keys in the version they already run (`RELEASE_KEYS` in `checker/releases.py`), and
those can't be changed from outside.

- **Lost:** no new release can be signed that an installed machine would accept, so each one has to be
  installed again with a version carrying a new key. Keep the offline copies in more than one place.
- **Stolen:** whoever has it can sign a release that machines would accept, if they can also get it in front
  of them. Say so publicly at once, and publish a release carrying a new key and dropping the old one,
  signed with the old key while that's still believed. Machines that take it stop trusting the stolen key;
  machines that don't remain exposed, so the notice has to reach people some other way too.
