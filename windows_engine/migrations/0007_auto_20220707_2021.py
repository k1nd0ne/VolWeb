# Generated by Django 3.2.13 on 2022-07-07 20:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('windows_engine', '0006_auto_20220707_1937'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userassist',
            name='Count',
            field=models.TextField(null=True),
        ),
        migrations.AlterField(
            model_name='userassist',
            name='FocusCount',
            field=models.TextField(null=True),
        ),
        migrations.AlterField(
            model_name='userassist',
            name='HiveName',
            field=models.TextField(null=True),
        ),
        migrations.AlterField(
            model_name='userassist',
            name='ID',
            field=models.TextField(null=True),
        ),
        migrations.AlterField(
            model_name='userassist',
            name='LastWriteTime',
            field=models.TextField(null=True),
        ),
        migrations.AlterField(
            model_name='userassist',
            name='Name',
            field=models.TextField(null=True),
        ),
        migrations.AlterField(
            model_name='userassist',
            name='Path',
            field=models.TextField(null=True),
        ),
        migrations.AlterField(
            model_name='userassist',
            name='RawData',
            field=models.TextField(null=True),
        ),
        migrations.AlterField(
            model_name='userassist',
            name='TimeFocused',
            field=models.TextField(null=True),
        ),
        migrations.AlterField(
            model_name='userassist',
            name='Type',
            field=models.TextField(null=True),
        ),
    ]