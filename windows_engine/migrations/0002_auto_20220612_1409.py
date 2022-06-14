# Generated by Django 3.2.13 on 2022-06-12 14:09

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('investigations', '0001_initial'),
        ('windows_engine', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='cachedump',
            name='investigation',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='windows_cachedump_investigation', to='investigations.uploadinvestigation'),
        ),
        migrations.AlterField(
            model_name='cmdline',
            name='investigation',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='windows_cmdline_investigation', to='investigations.uploadinvestigation'),
        ),
        migrations.AlterField(
            model_name='envars',
            name='investigation',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='windows_envars_investigation', to='investigations.uploadinvestigation'),
        ),
        migrations.AlterField(
            model_name='filedump',
            name='case_id',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='windows_filedump_investigation', to='investigations.uploadinvestigation'),
        ),
        migrations.AlterField(
            model_name='filescan',
            name='investigation',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='windows_filescan_investigation', to='investigations.uploadinvestigation'),
        ),
        migrations.AlterField(
            model_name='hashdump',
            name='investigation',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='windows_hashdump_investigation', to='investigations.uploadinvestigation'),
        ),
        migrations.AlterField(
            model_name='hivelist',
            name='investigation',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='windows_hivelist_investigation', to='investigations.uploadinvestigation'),
        ),
        migrations.AlterField(
            model_name='lsadump',
            name='investigation',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='windows_lsadump_investigation', to='investigations.uploadinvestigation'),
        ),
        migrations.AlterField(
            model_name='malfind',
            name='investigation',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='windows_malfind_investigation', to='investigations.uploadinvestigation'),
        ),
        migrations.AlterField(
            model_name='netgraph',
            name='investigation',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='windows_netgraph_investigation', to='investigations.uploadinvestigation'),
        ),
        migrations.AlterField(
            model_name='netscan',
            name='investigation',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='windows_netscan_investigation', to='investigations.uploadinvestigation'),
        ),
        migrations.AlterField(
            model_name='netstat',
            name='investigation',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='windows_netstat_investigation', to='investigations.uploadinvestigation'),
        ),
        migrations.AlterField(
            model_name='privs',
            name='investigation',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='windows_privs_investigation', to='investigations.uploadinvestigation'),
        ),
        migrations.AlterField(
            model_name='processdump',
            name='case_id',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='windows_processdump_investigation', to='investigations.uploadinvestigation'),
        ),
        migrations.AlterField(
            model_name='psscan',
            name='investigation',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='windows_psscan_investigation', to='investigations.uploadinvestigation'),
        ),
        migrations.AlterField(
            model_name='pstree',
            name='investigation',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='windows_pstree_investigation', to='investigations.uploadinvestigation'),
        ),
        migrations.AlterField(
            model_name='skeletonkeycheck',
            name='investigation',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='windows_skc_investigation', to='investigations.uploadinvestigation'),
        ),
        migrations.AlterField(
            model_name='strings',
            name='investigation',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='windows_strings_investigation', to='investigations.uploadinvestigation'),
        ),
        migrations.AlterField(
            model_name='timelinechart',
            name='investigation',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='windows_timeline_investigation', to='investigations.uploadinvestigation'),
        ),
        migrations.AlterField(
            model_name='timeliner',
            name='investigation',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='windows_timeliner_investigation', to='investigations.uploadinvestigation'),
        ),
    ]