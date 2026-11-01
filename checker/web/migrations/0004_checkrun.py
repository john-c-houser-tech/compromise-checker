from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("web", "0003_wrongconfirmation")]
    operations = [
        migrations.CreateModel(
            name="CheckRun",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                ("kind", models.CharField(max_length=16)),
                ("hosts", models.TextField()),
                ("who", models.CharField(max_length=150)),
                ("address", models.CharField(max_length=64)),
                ("started_at", models.DateTimeField(db_index=True)),
                ("finished_at", models.DateTimeField(null=True)),
                ("exit_status", models.IntegerField(null=True)),
                ("ended", models.CharField(default="", max_length=200)),
            ],
        ),
    ]
