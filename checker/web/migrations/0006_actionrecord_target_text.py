from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("web", "0005_access_invitation")]
    operations = [
        migrations.AlterField(model_name="actionrecord", name="target", field=models.TextField()),
    ]
