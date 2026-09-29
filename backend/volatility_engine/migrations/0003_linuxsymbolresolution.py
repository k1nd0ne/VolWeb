import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("evidences", "0001_initial"),
        ("symbols", "0001_initial"),
        ("volatility_engine", "0002_volatilityplugin_error_message"),
    ]

    operations = [
        migrations.CreateModel(
            name="LinuxSymbolResolution",
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
                    "status",
                    models.CharField(
                        choices=[
                            ("detecting", "Detecting banner"),
                            ("resolving", "Resolving ISF"),
                            ("verifying", "Verifying ISF"),
                            ("ready", "Ready"),
                            ("failed_banner", "Banner not found"),
                            ("failed_isf", "ISF not found"),
                        ],
                        default="detecting",
                        max_length=20,
                    ),
                ),
                ("banner", models.TextField(blank=True, null=True)),
                (
                    "method",
                    models.CharField(
                        blank=True,
                        choices=[
                            ("remote", "Remote index"),
                            ("manual", "Manual upload"),
                        ],
                        max_length=20,
                        null=True,
                    ),
                ),
                ("guidance", models.JSONField(blank=True, null=True)),
                ("message", models.TextField(blank=True, null=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "evidence",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="isf_resolution",
                        to="evidences.evidence",
                    ),
                ),
                (
                    "linked_symbol",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        to="symbols.symbol",
                    ),
                ),
            ],
        ),
    ]
