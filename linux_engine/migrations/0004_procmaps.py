# Generated by Django 3.2.13 on 2022-06-13 08:06

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('investigations', '0001_initial'),
        ('linux_engine', '0003_bash'),
    ]

    operations = [
        migrations.CreateModel(
            name='ProcMaps',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('End', models.BigIntegerField(null=True)),
                ('FilePath', models.CharField(max_length=255, null=True)),
                ('Flags', models.CharField(max_length=20, null=True)),
                ('Command', models.CharField(max_length=500, null=True)),
                ('Inode', models.BigIntegerField(null=True)),
                ('Major', models.BigIntegerField(null=True)),
                ('Minor', models.BigIntegerField(null=True)),
                ('PID', models.BigIntegerField(null=True)),
                ('PgOff', models.BigIntegerField(null=True)),
                ('Process', models.CharField(max_length=255, null=True)),
                ('Start', models.BigIntegerField(null=True)),
                ('investigation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='linux_procmaps_investigation', to='investigations.uploadinvestigation')),
            ],
        ),
    ]
