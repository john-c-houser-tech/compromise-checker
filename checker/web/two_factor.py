"""The second step at sign-in: codes from an authenticator app, and one-time recovery codes, since
a small business has no help desk when a phone is lost. django-otp checks the codes, refuses one
used twice, and makes each wrong code wait longer than the last, up to a limit here: anyone with the
password can cause that wait, and it falls on the account's owner too."""

from __future__ import annotations

import base64

from django.db import transaction
from django_otp import devices_for_user, user_has_device, verify_token
from django_otp.plugins.otp_static.models import StaticDevice, StaticToken
from django_otp.plugins.otp_totp.models import TOTPDevice
from markupsafe import Markup

RECOVERY_CODES = 10
MOST_WRONG_CODES_COUNTED = 10  # each one doubles the wait, so this is about 9 minutes at worst
PENDING = "two_factor_pending"
SAVED, UNSAVED = "recovery codes", "recovery codes, not known to be saved"


def is_on(user) -> bool:
    return user_has_device(user)


def pending(request) -> TOTPDevice | None:
    """Only the one this session started. Someone else's, a thief's above all, must never be what
    the owner ends up scanning."""
    return TOTPDevice.objects.filter(
        pk=request.session.get(PENDING), user=request.user, confirmed=False
    ).first()


def start(request) -> TOTPDevice:
    """A fresh secret each time: one seen earlier, by anyone, is no use afterwards."""
    with transaction.atomic():
        forget_pending(request.user)
        device = TOTPDevice.objects.create(user=request.user, name="authenticator", confirmed=False)
    request.session[PENDING] = device.pk
    return device


def pending_devices_for(user):
    return TOTPDevice.objects.filter(user=user, confirmed=False)


def forget_pending(user) -> None:
    TOTPDevice.objects.filter(user=user, confirmed=False).delete()


def qr_code(device: TOTPDevice) -> Markup:
    """Drawn here, so the secret never goes to a service that makes QR codes."""
    import segno  # only here, so a missing one can't take every page down with it

    return Markup(  # noqa: S704 - segno's own output, from the tool's own secret
        segno.make(device.config_url, error="m").svg_inline(
            scale=5, border=4, dark="#000", light="#fff"
        )
    )


def secret_text(device: TOTPDevice) -> str:
    """In groups of four, for typing into an app by hand."""
    secret = base64.b32encode(device.bin_key).decode().rstrip("=")
    return " ".join(secret[i : i + 4] for i in range(0, len(secret), 4))


def _clean(code: str) -> str:
    return "".join(code.split()).lower()


def check_code(user, code: str):
    """The device a code belongs to, or None. Six digits go only to the app and anything else only
    to the recovery codes, so a recovery code doesn't count as a wrong code from the app."""
    for model in (TOTPDevice, StaticDevice):
        model.objects.filter(
            user=user, throttling_failure_count__gt=MOST_WRONG_CODES_COUNTED
        ).update(throttling_failure_count=MOST_WRONG_CODES_COUNTED)
    code = _clean(code)
    six_digits = code.isdigit() and len(code) == 6
    kind = TOTPDevice if six_digits else StaticDevice
    for device in devices_for_user(user):
        if isinstance(device, kind) and verify_token(user, device.persistent_id, code):
            return device
    return None


def used_recovery_code(device) -> bool:
    return isinstance(device, StaticDevice)


def turn_on(request, code: str):
    """The app's device and new recovery codes if the code is right, or None. All at once, so a
    double-click can't make two sets."""
    with transaction.atomic():
        device = pending(request)
        if is_on(request.user) or device is None or not device.verify_token(_clean(code)):
            return None
        device.confirmed = True
        device.save(update_fields=["confirmed"])
        forget_pending(request.user)
        return device, new_recovery_codes(request.user)


def new_recovery_codes(user) -> list[str]:
    """Replaces any before them, keeping the device, since a session may have signed in with it.
    Only the caller sees the list, once, and they aren't known to be saved until someone says so."""
    with transaction.atomic():
        device = StaticDevice.objects.filter(user=user).first()
        if device is None:
            device = StaticDevice.objects.create(user=user, name=UNSAVED, confirmed=True)
        StaticDevice.objects.filter(pk=device.pk).update(name=UNSAVED)
        StaticToken.objects.filter(device=device).delete()
        codes = [StaticToken.random_token() for _ in range(RECOVERY_CODES)]
        StaticToken.objects.bulk_create(StaticToken(device=device, token=code) for code in codes)
    return codes


def codes_unsaved(user) -> bool:
    return StaticDevice.objects.filter(user=user, name=UNSAVED).exists()


def mark_codes_saved(user) -> None:
    StaticDevice.objects.filter(user=user).update(name=SAVED)


def forgive_wrong_codes(user) -> None:
    """After a new password: whoever caused the wait no longer gets to."""
    for model in (TOTPDevice, StaticDevice):
        model.objects.filter(user=user).update(
            throttling_failure_count=0, throttling_failure_timestamp=None
        )


def recovery_codes_left(user) -> int:
    return StaticToken.objects.filter(device__user=user).count()


def turn_off(user) -> None:
    with transaction.atomic():
        TOTPDevice.objects.filter(user=user).delete()
        StaticDevice.objects.filter(user=user).delete()
