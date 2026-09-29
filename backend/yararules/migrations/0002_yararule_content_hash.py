from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("yararules", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="yararule",
            name="content_hash",
            field=models.CharField(
                blank=True, db_index=True, max_length=64, null=True
            ),
        ),
    ]
