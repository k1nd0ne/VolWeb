# Generated by Django 3.2.18 on 2023-04-23 10:53

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('investigations', '0001_initial'),
        ('windows_engine', '0021_auto_20230105_2038'),
    ]

    operations = [
        migrations.CreateModel(
            name='DriverModule',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('AlternativeName', models.TextField(null=True)),
                ('DriverName', models.TextField(null=True)),
                ('KnownException', models.TextField(null=True)),
                ('Offset', models.TextField(null=True)),
                ('ServiceKey', models.TextField()),
                ('investigation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='windows_drivermodule_investigation', to='investigations.uploadinvestigation')),
            ],
        ),
    ]