import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("yararulesets", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="YaraRule",
            fields=[
                ("id", models.AutoField(primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=250)),
                ("etag", models.CharField(max_length=256, unique=True)),
                ("rule_content", models.TextField()),
                ("description", models.TextField(blank=True, null=True)),
                ("status", models.IntegerField(default=0)),
                ("url", models.TextField(null=True)),
                (
                    "source",
                    models.CharField(
                        choices=[("custom", "manual"), ("github", "github")],
                        max_length=10,
                        null=True,
                    ),
                ),
                ("is_active", models.BooleanField(default=True)),
                (
                    "linked_yararuleset",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to="yararulesets.yararuleset",
                    ),
                ),
            ],
        ),
    ]
