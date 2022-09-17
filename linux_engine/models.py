from django.db import models
from investigations.models import *

TAGS = (
        ('Evidence', 'Evidence'),
        ('Suspicious', 'Suspicious'),
    )

class PsTree(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
            related_name="linux_pstree_investigation"
        )
    graph = models.JSONField(null = True)

class PsList(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
            related_name="linux_pslist_investigation"
        )
    COMM = models.CharField(max_length = 255,null = True)
    PID = models.BigIntegerField(null = True)
    PPID = models.BigIntegerField(null = True)

class Bash(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
            related_name="linux_bash_investigation"
        )
    PID = models.BigIntegerField(null = True)
    Process = models.CharField(max_length = 255,null = True)
    CommandTime = models.CharField(max_length = 255,null = True)
    Command = models.CharField(max_length = 500,null = True)
    Tag = models.CharField(null = True, max_length = 11, choices = TAGS)


class ProcMaps(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
            related_name="linux_procmaps_investigation"
        )
    End = models.BigIntegerField(null = True)
    FilePath = models.CharField(max_length = 255,null = True)
    Flags = models.CharField(max_length = 20,null = True)
    Command = models.CharField(max_length = 500,null = True)
    Inode = models.BigIntegerField(null = True)
    Major = models.BigIntegerField(null = True)
    Minor = models.BigIntegerField(null = True)
    PID = models.BigIntegerField(null = True)
    PgOff = models.BigIntegerField(null = True)
    Process = models.CharField(max_length = 255,null = True)
    Start = models.BigIntegerField(null = True)
    Tag = models.CharField(null = True, max_length = 11, choices = TAGS)


class Lsof(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
            related_name="linux_lsof_investigation"
        )
    FD = models.BigIntegerField(null = True)
    PID = models.BigIntegerField(null = True)
    Path = models.CharField(max_length = 255,null = True)
    Process = models.CharField(max_length = 500,null = True)
    Tag = models.CharField(null = True, max_length = 11, choices = TAGS)


class TtyCheck(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
            related_name="linux_ttycheck_investigation"
        )
    Address = models.BigIntegerField(null = True)
    Module = models.CharField(max_length = 255,null = True)
    Name = models.CharField(max_length = 255,null = True)
    Symbol = models.CharField(max_length = 255,null = True)
    Tag = models.CharField(null = True, max_length = 11, choices = TAGS)


class Elfs(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
            related_name="linux_elfs_investigation"
        )
    End = models.BigIntegerField(null = True)
    FilePath = models.CharField(max_length = 255,null = True)
    PID = models.BigIntegerField(null = True)
    Process = models.CharField(max_length = 255,null = True)
    Start = models.BigIntegerField(null = True)
    Tag = models.CharField(null = True, max_length = 11, choices = TAGS)
