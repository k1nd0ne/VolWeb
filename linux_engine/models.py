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
    graph = models.JSONField(null=True)


class PsList(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="linux_pslist_investigation"
    )
    COMM = models.TextField(null=True)
    Offset = models.BigIntegerField(null=True)
    PID = models.BigIntegerField(null=True)
    PPID = models.BigIntegerField(null=True)
    TID = models.BigIntegerField(null=True)

class PsAux(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="linux_psaux_investigation"
    )
    ARGS = models.TextField(null=True)
    COMM = models.TextField(null=True)
    PID = models.BigIntegerField(null=True)
    PPID = models.BigIntegerField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)


class Bash(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="linux_bash_investigation"
    )
    PID = models.BigIntegerField(null=True)
    Process = models.TextField(null=True)
    CommandTime = models.TextField(null=True)
    Command = models.CharField(max_length=500, null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)


class ProcMaps(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="linux_procmaps_investigation"
    )
    End = models.BigIntegerField(null=True)
    FilePath = models.TextField(null=True)
    Flags = models.CharField(max_length=20, null=True)
    Command = models.CharField(max_length=500, null=True)
    Inode = models.BigIntegerField(null=True)
    Major = models.BigIntegerField(null=True)
    Minor = models.BigIntegerField(null=True)
    PID = models.BigIntegerField(null=True)
    PgOff = models.BigIntegerField(null=True)
    Process = models.TextField(null=True)
    Start = models.BigIntegerField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)


class Lsof(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="linux_lsof_investigation"
    )
    FD = models.BigIntegerField(null=True)
    PID = models.BigIntegerField(null=True)
    Path = models.TextField(null=True)
    Process = models.CharField(max_length=500, null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)


class TtyCheck(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="linux_ttycheck_investigation"
    )
    Address = models.BigIntegerField(null=True)
    Module = models.TextField(null=True)
    Name = models.TextField(null=True)
    Symbol = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)


class Elfs(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="linux_elfs_investigation"
    )
    End = models.BigIntegerField(null=True)
    FilePath = models.TextField(null=True)
    PID = models.BigIntegerField(null=True)
    Process = models.TextField(null=True)
    Start = models.BigIntegerField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)


class MountInfo(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="linux_mountinfo_investigation"
    )
    FIELDS = models.TextField(null=True)
    FSTYPE = models.TextField(null=True)
    MAJOR_MINOR = models.TextField(max_length=20, null=True)
    MNT_NS_ID = models.TextField(max_length=500, null=True)
    MOUNTID = models.BigIntegerField(null=True)
    MOUNT_OPTIONS = models.TextField(null=True)
    MOUNT_POINT = models.TextField(null=True)
    MOUNT_SRC = models.TextField(null=True)
    PARENT_ID = models.BigIntegerField(null=True)
    ROOT = models.TextField(null=True)
    SB_OPTIONS = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)

class Sockstat(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="linux_sockstat_investigation"
    )
    DestinationAddr = models.TextField(null=True)
    DestinationPort = models.TextField(null=True)
    FD = models.BigIntegerField(null=True)
    Family = models.TextField(null=True)
    Filter = models.TextField(null=True)
    NetNS = models.TextField(null=True)
    Pid = models.BigIntegerField(null=True)
    Proto = models.TextField(null=True)
    SockOffset = models.TextField(null=True)
    SourceAddr = models.TextField(null=True)
    SourcePort = models.TextField(null=True)
    State = models.TextField(null=True)
    Type = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)


class Envars(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="linux_envars_investigation"
    )
    COMM = models.TextField(null=True)
    KEY = models.TextField(null=True)
    PID = models.BigIntegerField(null=True)
    PPID = models.BigIntegerField(null=True)
    VALUE = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)

class TimeLineChart(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="linux_timeline_investigation"
    )
    graph = models.JSONField(null=True)

class Timeliner(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="linux_timeliner_investigation"
    )
    Plugin = models.TextField(null=True)
    Description = models.TextField(null=True)
    AccessedDate = models.TextField(null=True)
    ChangedDate = models.TextField(null=True)
    CreatedDate = models.TextField(null=True)
    ModifiedDate = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)
