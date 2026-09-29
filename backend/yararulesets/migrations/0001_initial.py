import django.db.models.deletion
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="YaraRuleSet",
            fields=[
                ("id", models.AutoField(primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=200, unique=True)),
                ("description", models.TextField(blank=True, null=True)),
                ("is_default", models.BooleanField(default=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("compiled_rules", models.BinaryField(blank=True, null=True)),
                ("status", models.IntegerField(default=0)),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
        migrations.CreateModel(
            name="UploadSession",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "upload_id",
                    models.UUIDField(default=uuid.uuid4, editable=False, unique=True),
                ),
                ("filename", models.CharField(max_length=255)),
                ("description", models.TextField(blank=True, null=True)),
                ("source", models.CharField(max_length=255, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "yararuleset",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to="yararulesets.yararuleset",
                    ),
                ),
            ],
        ),
    ]
