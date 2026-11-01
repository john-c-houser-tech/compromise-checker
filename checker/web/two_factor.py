"""The second step at sign-in: codes from an authenticator app, and one-time recovery codes, since
a small business has no help desk when a phone is lost. django-otp checks the codes, refuses one
used twice, and makes each wrong code wait longer than the last."""

from __future__ import annotations

import base64

import segno
from django.db import transaction
from django_otp import devices_for_user, user_has_device, verify_token
from django_otp.plugins.otp_static.models import StaticDevice, StaticToken
from django_otp.plugins.otp_totp.models import TOTPDevice
from markupsafe import Markup

RECOVERY_CODES = 10


def is_on(user) -> bool:
    return user_has_device(user)


def pending(user) -> TOTPDevice | None:
    return TOTPDevice.objects.filter(user=user, confirmed=False).first()


def start(user) -> None:
    """A fresh secret each time: one seen earlier, by anyone, is no use afterwards."""
    with transaction.atomic():
        TOTPDevice.objects.filter(user=user, confirmed=False).delete()
        TOTPDevice.objects.create(user=user, name="authenticator", confirmed=False)


def qr_code(device: TOTPDevice) -> Markup:
    """Drawn here, so the secret never goes to a service that makes QR codes."""
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
    code = _clean(code)
    six_digits = code.isdigit() and len(code) == 6
    kind = TOTPDevice if six_digits else StaticDevice
    for device in devices_for_user(user):
        if isinstance(device, kind) and verify_token(user, device.persistent_id, code):
            return device
    return None


def used_recovery_code(device) -> bool:
    return isinstance(device, StaticDevice)


def turn_on(user, code: str):
    """The app's device and new recovery codes if the code is right, or None. All at once, so a
    double-click can't make two sets."""
    with transaction.atomic():
        device = pending(user)
        if is_on(user) or device is None or not device.verify_token(_clean(code)):
            return None
        device.confirmed = True
        device.save(update_fields=["confirmed"])
        return device, new_recovery_codes(user)


def new_recovery_codes(user) -> list[str]:
    """Replaces any before them. Only the caller sees the list, once."""
    with transaction.atomic():
        StaticDevice.objects.filter(user=user).delete()
        device = StaticDevice.objects.create(user=user, name="recovery codes", confirmed=True)
        codes = [StaticToken.random_token() for _ in range(RECOVERY_CODES)]
        StaticToken.objects.bulk_create(StaticToken(device=device, token=code) for code in codes)
    return codes


def recovery_codes_left(user) -> int:
    return StaticToken.objects.filter(device__user=user).count()


def turn_off(user) -> None:
    with transaction.atomic():
        TOTPDevice.objects.filter(user=user).delete()
        StaticDevice.objects.filter(user=user).delete()
