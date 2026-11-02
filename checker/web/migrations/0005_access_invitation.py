from django.conf import settings
from django.db import migrations, models


def _everyone_so_far_keeps_full_access(apps, schema_editor):
    """Whoever already had an account could do everything, and the last of them mustn't be locked
    out by an upgrade."""
    access = apps.get_model("web", "Access")
    user = apps.get_model(*settings.AUTH_USER_MODEL.split("."))
    alias = schema_editor.connection.alias  # a move migrates a file that isn't the default database
    for pk in user.objects.using(alias).values_list("pk", flat=True):
        access.objects.using(alias).create(user_id=pk, full=True)


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("web", "0004_checkrun"),
    ]
    operations = [
        migrations.CreateModel(
            name="Access",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                ("full", models.BooleanField(default=False)),
                (
                    "user",
                    models.OneToOneField(
                        on_delete=models.CASCADE,
                        related_name="access",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="Invitation",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                ("token_hash", models.CharField(max_length=64, unique=True)),
                ("expires_at", models.DateTimeField()),
                (
                    "user",
                    models.OneToOneField(
                        on_delete=models.CASCADE,
                        related_name="invitation",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.RunPython(_everyone_so_far_keeps_full_access, migrations.RunPython.noop),
    ]
