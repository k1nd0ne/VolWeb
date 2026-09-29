from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("volatility_engine", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="volatilityplugin",
            name="error_message",
            field=models.TextField(blank=True, null=True),
        ),
    ]
