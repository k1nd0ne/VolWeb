# Generated by Django 5.1.1 on 2024-11-01 14:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("evidences", "0003_alter_evidence_os"),
    ]

    operations = [
        migrations.AddField(
            model_name="evidence",
            name="output_path",
            field=models.CharField(default="", editable=False, max_length=255),
        ),
    ]