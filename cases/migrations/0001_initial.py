# Generated by Django 4.2.4 on 2024-03-24 11:53

from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Case",
            fields=[
                ("case_id", models.AutoField(primary_key=True, serialize=False)),
                ("case_bucket_id", models.UUIDField()),
                ("case_name", models.CharField(max_length=500)),
                ("case_description", models.TextField()),
                ("case_last_update", models.DateField(auto_now=True)),
                ("linked_users", models.ManyToManyField(to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
