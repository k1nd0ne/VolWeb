from django.db import models

# Create your models here.
from django.db import models
from evidences.models import Evidence
import base64

TAGS = (
    ("Evidence", "Evidence"),
    ("Suspicious", "Suspicious"),
    ("Clear", "Clear"),
)


class ProcessDump(models.Model):
    process_dump_id = models.AutoField(primary_key=True)
    dump_id = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_processdump_evidence"
    )
    pid = models.BigIntegerField()
    filename = models.TextField(null=True)


class FileDump(models.Model):
    file_dump_id = models.AutoField(primary_key=True)
    dump_id = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_filedump_evidence"
    )
    offset = models.TextField(null=True)
    filename = models.TextField(null=True)


class PsTree(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_pstree_evidence"
    )
    graph = models.JSONField(null=True)


class DeviceTree(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_devicetree_evidence"
    )
    graph = models.JSONField(null=True)


class NetGraph(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_netgraph_evidence"
    )
    graph = models.JSONField(null=True)


class TimeLineChart(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_timeline_evidence"
    )
    graph = models.JSONField(null=True)


class PsScan(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_psscan_evidence"
    )
    PID = models.BigIntegerField(null=True)
    PPID = models.BigIntegerField(null=True)
    ImageFileName = models.TextField(null=True)
    Offset = models.TextField(null=True)
    Threads = models.BigIntegerField(null=True)
    Handles = models.BigIntegerField(null=True)
    SessionId = models.TextField(null=True)
    Wow64 = models.BooleanField()
    CreateTime = models.TextField(null=True)
    ExitTime = models.TextField(null=True)
    Fileoutput = models.TextField(null=True)


class CmdLine(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_cmdline_evidence"
    )
    PID = models.BigIntegerField(null=True)
    Process = models.TextField(null=True)
    Args = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)


class Privs(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_privs_evidence"
    )
    PID = models.BigIntegerField(null=True)
    Process = models.TextField(null=True)
    Value = models.TextField(null=True)
    Privilege = models.TextField(null=True)
    Attributes = models.TextField(null=True)
    Description = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)


class Sessions(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_sessions_evidence"
    )
    CreateTime = models.TextField(null=True)
    Process = models.TextField(null=True)
    ProcessID = models.BigIntegerField(null=True)
    SessionID = models.BigIntegerField(null=True)
    SessionType = models.TextField(null=True)
    UserName = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)


class GetSIDs(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_getsids_evidence"
    )
    Name = models.TextField(null=True)
    PID = models.BigIntegerField(null=True)
    Process = models.TextField(null=True)
    SID = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)


class LdrModules(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_ldrmodules_evidence"
    )
    Base = models.TextField(null=True)
    InInit = models.TextField(null=True)
    InLoad = models.TextField(null=True)
    InMem = models.TextField(null=True)
    MappedPath = models.TextField(null=True)
    Pid = models.BigIntegerField(null=True)
    Process = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)

class Modules(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_modules_evidence"
    )
    Base = models.TextField(null=True)
    Fileoutput = models.TextField(null=True)
    Name = models.TextField(null=True)
    Offset = models.TextField(null=True)
    Path = models.TextField(null=True)
    Size = models.BigIntegerField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)

class Envars(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_envars_evidence"
    )
    PID = models.BigIntegerField(null=True)
    Process = models.TextField(null=True)
    Block = models.TextField(null=True)
    Variable = models.TextField(null=True)
    Value = models.TextField(null=True)
    Description = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)


class NetScan(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_netscan_evidence"
    )
    Offset = models.TextField(null=True)
    Proto = models.TextField(null=True)
    LocalAddr = models.TextField(null=True)
    LocalPort = models.TextField(null=True)
    ForeignAddr = models.TextField(null=True)
    ForeignPort = models.TextField(null=True)
    State = models.TextField(null=True)
    PID = models.BigIntegerField(null=True)
    Owner = models.TextField(null=True)
    Created = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)


class NetStat(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_netstat_evidence"
    )
    Offset = models.TextField(null=True)
    Proto = models.TextField(null=True)
    LocalAddr = models.TextField(null=True)
    LocalPort = models.TextField(null=True)
    ForeignAddr = models.TextField(null=True)
    ForeignPort = models.TextField(null=True)
    State = models.TextField(null=True)
    PID = models.BigIntegerField(null=True)
    Owner = models.TextField(null=True)
    Created = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)


class Hashdump(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_hashdump_evidence"
    )
    User = models.TextField(null=True)
    rid = models.TextField(null=True)
    lmhash = models.TextField(null=True)
    nthash = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)


class Lsadump(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_lsadump_evidence"
    )
    Key = models.TextField(null=True)
    Secret = models.TextField(null=True)
    Hex = models.TextField(null=True)

    def save(self, *args, **kwargs):
        self.Secret = base64.b64encode(bytes(self.Secret, "utf-8"))
        super().save(*args, **kwargs)


class Cachedump(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_cachedump_evidence"
    )
    Domain = models.TextField(null=True)
    Domainname = models.TextField(null=True)
    Hash = models.TextField(null=True)
    Username = models.TextField(null=True)


class HiveList(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_hivelist_evidence"
    )
    FileFullPath = models.TextField(null=True)
    Offset = models.TextField(null=True)
    Fileoutput = models.TextField(null=True)


class Timeliner(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_timeliner_evidence"
    )
    Plugin = models.TextField(null=True)
    Description = models.TextField(null=True)
    AccessedDate = models.TextField(null=True)
    ChangedDate = models.TextField(null=True)
    CreatedDate = models.TextField(null=True)
    ModifiedDate = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)


class SkeletonKeyCheck(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_skc_evidence"
    )
    PID = models.BigIntegerField(null=True)
    Process = models.TextField(null=True)
    SkeletonKeyFound = models.TextField(null=True)
    rc4HmacInitialize = models.TextField(null=True)
    rc4HmacDecrypt = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)


class Malfind(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_malfind_evidence"
    )

    PID = models.BigIntegerField(null=True)
    Process = models.TextField(null=True)
    StartVPN = models.TextField(null=True)
    EndVPN = models.TextField(null=True)
    VTag = models.TextField(null=True)
    Protection = models.TextField(null=True)
    CommitCharge = models.TextField(null=True)
    PrivateMemory = models.TextField(null=True)
    Fileoutput = models.TextField(null=True)
    Hexdump = models.TextField(null=True)
    Disasm = models.TextField(null=True)


class UserAssist(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_userassist_evidence"
    )
    HiveOffset = models.TextField(null=True)
    HiveName = models.TextField(null=True)
    Path = models.TextField(null=True)
    LastWriteTime = models.TextField(null=True)
    Type = models.TextField(null=True)
    Name = models.TextField(null=True)
    ID = models.TextField(null=True)
    Count = models.TextField(null=True)
    FocusCount = models.TextField(null=True)
    TimeFocused = models.TextField(null=True)
    LastUpdated = models.TextField(null=True)
    RawData = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)


class FileScan(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_filescan_evidence"
    )
    Offset = models.TextField(null=True)
    Name = models.TextField(null=True)
    Size = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)


class Strings(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_strings_evidence"
    )
    String = models.TextField(null=True)
    PhysicalAddress = models.TextField(null=True)
    Result = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)


class DllList(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_dllist_evidence"
    )
    Process = models.TextField(null=True)
    PID = models.BigIntegerField(null=True)
    Base = models.TextField(null=True)
    Name = models.TextField(null=True)
    Path = models.TextField(null=True)
    Size = models.TextField(null=True)
    LoadTime = models.TextField(null=True)
    Fileoutput = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)


class Handles(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_handles_evidence"
    )
    Process = models.TextField(null=True)
    PID = models.BigIntegerField()
    Offset = models.TextField(null=True)
    Name = models.TextField(null=True)
    HandleValue = models.IntegerField(null=True)
    GrantedAccess = models.TextField(null=True)
    Type = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)


class DriverModule(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_drivermodule_evidence"
    )
    AlternativeName = models.TextField(null=True)
    DriverName = models.TextField(null=True)
    KnownException = models.TextField(null=True)
    Offset = models.TextField(null=True)
    ServiceKey = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)


class VadWalk(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_vadwalk_evidence"
    )
    End = models.TextField(null=True)
    Left = models.TextField(null=True)
    Offset = models.TextField(null=True)
    PID = models.BigIntegerField()
    Parent = models.TextField(null=True)
    Process = models.TextField(null=True)
    Right = models.TextField(null=True)
    Start = models.TextField(null=True)
    VTag = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)

