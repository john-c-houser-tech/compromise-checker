#!/bin/bash
# Compromise Checker @VERSION@ on a new Linode (installation plan I.7). This is Linode's "form":
# the fields below are what Cloud Manager asks, and nothing here is secret. (A field whose name has
# "password" in it would be shown masked, so the SSH-password question is named otherwise.) It
# downloads the release, checks the installer against the hash fixed in this script, and runs the
# same installer the pasted line does, with your answers. When it's done, the link for creating the
# first account appears above the login prompt in the Lish console, and in
# /var/log/compromise-checker-install.log.
#
# <UDF name="web_address" label="Web address" example="A name you own, such as checker.example.org. After this Linode is created, point that name's DNS record at the Linode's IPv4 address; the installer waits up to 30 minutes for it. For a trial, type auto to get a name at sslip.io made from the address." />
# <UDF name="allowed" label="Addresses allowed to open the page (optional)" default="" example="Addresses or ranges, apart by spaces, such as 203.0.113.10 198.51.100.0/24: the office, say. Empty: anyone with an account." />
# <UDF name="root_login_off" label="Turn off SSH logins as root" oneOf="no,yes" default="no" example="Only done if another administrator account can already log in; otherwise the installer leaves it on and says why." />
# <UDF name="ssh_key_logins_only" label="Turn off SSH logins with a password" oneOf="no,yes" default="no" example="Only done once an administrator has logged in with an SSH key, which on a new Linode hasn't happened yet: the page then says how to turn passwords off later." />
# <UDF name="block_login_failures" label="Hold off addresses that keep failing to log in over SSH" oneOf="no,yes" default="no" />

set -u
LOG=/var/log/compromise-checker-install.log
exec > >(tee -a "$LOG") 2>&1
echo "Compromise Checker @VERSION@: starting the install at $(date -u +%FT%TZ)."

VERSION="@VERSION@"
INSTALLER_SHA256="@INSTALLER_SHA256@"
DOWNLOADS="@DOWNLOADS@"
WHEEL="checker-$VERSION-py3-none-any.whl"

stop() { echo "STOPPED: $1"; exit 1; }
command -v curl > /dev/null || stop "curl isn't on this image."
command -v python3 > /dev/null || stop "python3 isn't on this image."

work=$(mktemp -d) || stop "couldn't make a folder."
chmod 700 "$work"
for name in install.py release.json release.json.minisig requirements.lock "$WHEEL"; do
    curl -fsSL "$DOWNLOADS/v$VERSION/$name" -o "$work/$name" \
        || stop "couldn't download $name from $DOWNLOADS. Check this Linode's internet, and the version."
done
# The hash is what protects the installer; it checks the rest against the release key's signature.
echo "$INSTALLER_SHA256  $work/install.py" | sha256sum -c - > /dev/null \
    || stop "install.py isn't the file this script was made for. Nothing was installed."

WEB_ADDRESS="${WEB_ADDRESS:-}"
if [ "$WEB_ADDRESS" = "auto" ]; then
    address=$(curl -fsS -4 https://api.ipify.org || ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1)
    [ -n "$address" ] || stop "this Linode's address couldn't be told, so no name could be made."
    WEB_ADDRESS="${address//./-}.sslip.io"
    echo "Using the trial name $WEB_ADDRESS, which leads to this Linode's address."
fi
[ -n "$WEB_ADDRESS" ] || stop "a web address is needed: this Linode has no browser of its own."

flags=(--new-machine --console-notice --web-address "$WEB_ADDRESS")
[ -n "${ALLOWED:-}" ] && flags+=(--allow "$ALLOWED")  # one argument: the installer splits it
[ "${ROOT_LOGIN_OFF:-no}" = "yes" ] && flags+=(--root-login-off)
[ "${SSH_KEY_LOGINS_ONLY:-no}" = "yes" ] && flags+=(--ssh-passwords-off)
[ "${BLOCK_LOGIN_FAILURES:-no}" = "yes" ] && flags+=(--block-login-failures)
@EXTRA_FLAGS@

cd / || exit 1
python3 -I "$work/install.py" --from "$work" "${flags[@]}" < /dev/null
code=$?
rm -rf "$work"
if [ $code -ne 0 ]; then
    echo "The installer stopped (exit $code). Log in over SSH and read $LOG; running the pasted line from the install page continues it."
    exit $code
fi
echo "Done at $(date -u +%FT%TZ). The link for the first account is above the login prompt in the Lish console."
