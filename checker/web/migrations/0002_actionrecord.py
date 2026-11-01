from django.db import migrations, models

from checker.web.models import ACTION_RECORD_TRIGGERS


class Migration(migrations.Migration):
    dependencies = [("web", "0001_initial")]
    operations = [
        migrations.CreateModel(
            name="ActionRecord",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                ("at", models.DateTimeField(db_index=True)),
                ("who", models.CharField(max_length=150)),
                ("address", models.CharField(max_length=64)),
                ("action", models.CharField(max_length=64)),
                ("target", models.CharField(max_length=200)),
                ("outcome", models.CharField(max_length=32)),
                ("detail", models.TextField()),
            ],
        ),
        migrations.RunSQL(ACTION_RECORD_TRIGGERS, migrations.RunSQL.noop),
    ]
