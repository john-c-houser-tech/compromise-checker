from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("web", "0002_actionrecord")]
    operations = [
        migrations.CreateModel(
            name="WrongConfirmation",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                ("session_key", models.CharField(db_index=True, max_length=40)),
                ("at", models.DateTimeField(db_index=True)),
            ],
        ),
    ]
