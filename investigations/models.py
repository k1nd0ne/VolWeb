from django.db import models
import datetime, base64
#OS CHOICE
CHOICES = (
        ('Windows', 'Windows'),
#        ('Linux', 'Linux'), <- not implemented yet
#        ('MacOs', 'MacOs'), <- not implemented yet
    )

class UploadInvestigation(models.Model):
    id = models.AutoField(primary_key=True)
    title = models.CharField(max_length=500)
    os_version = models.CharField(max_length=50, choices = CHOICES)
    investigators = models.CharField(max_length=500)
    description = models.TextField(max_length=500)
    status = models.CharField(max_length=20)
    percentage = models.CharField(max_length=10)
    taskid = models.CharField(max_length=500)
    existingPath = models.CharField(unique=True, max_length=500)
    name = models.CharField(max_length=500)
    eof = models.BooleanField()
    uid = models.CharField(max_length=500)
    def __str__(self):
        return str(self.title)
    def update_activity(self, *args, **kwargs):
        try:
            activity = Activity.objects.get(date=datetime.datetime.now().date())
            activity.count = activity.count + 1
        except Activity.DoesNotExist:
            activity = Activity()
            activity.date = datetime.datetime.now().date()
            activity.count = 1
        activity.save()

class Activity(models.Model):
    date = models.DateField(primary_key=True)
    count = models.BigIntegerField()


class ImageSignature(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )
    md5 = models.CharField(max_length = 32,null = True)
    sha1 = models.CharField(max_length = 40,null = True)
    sha256 = models.CharField(max_length = 64,null = True)



class ProcessDump(models.Model):
    process_dump_id = models.AutoField(primary_key=True)
    case_id = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
    )
    pid = models.BigIntegerField()
    filename = models.CharField(max_length = 255)

class FileDump(models.Model):
    file_dump_id = models.AutoField(primary_key=True)
    case_id = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
    )
    offset = models.BigIntegerField(null = True)
    filename = models.CharField(max_length = 255)


class PsTree(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )
    graph = models.JSONField(null = True)

class NetGraph(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )
    graph = models.JSONField(null = True)

class TimeLineChart(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )
    graph = models.JSONField(null = True)

class PsScan(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )
    PID = models.BigIntegerField(null = True)
    PPID = models.BigIntegerField(null = True)
    ImageFileName = models.CharField(max_length = 255,null = True)
    Offset = models.BigIntegerField(null = True)
    Threads = models.BigIntegerField(null = True)
    Handles = models.BigIntegerField(null = True)
    SessionId = models.BigIntegerField(null = True)
    Wow64 = models.BooleanField()
    CreateTime = models.CharField(max_length = 255,null = True)
    ExitTime = models.CharField(max_length = 255,null = True)
    Fileoutput = models.CharField(max_length = 255,null = True)

class CmdLine(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )
    PID = models.BigIntegerField(null = True)
    Process = models.CharField(max_length=500, null = True)
    Args = models.CharField(max_length=500, null = True)


class Privs(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )
    PID = models.BigIntegerField(null = True)
    Process = models.CharField(max_length=500, null = True)
    Value = models.BigIntegerField(null = True)
    Privilege = models.CharField(max_length=500, null = True)
    Attributes = models.CharField(max_length=500, null = True)
    Description = models.CharField(max_length=500, null = True)

class Envars(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )
    PID = models.BigIntegerField(null = True)
    Process = models.CharField(max_length=500, null = True)
    Block = models.CharField(max_length=500, null = True)
    Variable = models.CharField(max_length=500, null = True)
    Value = models.CharField(max_length=500, null = True)
    Description = models.CharField(max_length=500, null = True)


class NetScan(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )
    Offset = models.BigIntegerField(null = True)
    Proto = models.CharField(max_length=500, null = True)
    LocalAddr = models.CharField(max_length=500, null = True)
    LocalPort = models.CharField(max_length=500, null = True)
    ForeignAddr = models.CharField(max_length=500, null = True)
    ForeignPort = models.CharField(max_length=500, null = True)
    State = models.CharField(max_length=500, null = True)
    PID = models.BigIntegerField(null = True)
    Owner = models.CharField(max_length=500, null = True)
    Created = models.CharField(max_length=500, null = True)

class NetStat(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )
    Offset = models.BigIntegerField(null = True)
    Proto = models.CharField(max_length=500, null = True)
    LocalAddr = models.CharField(max_length=500, null = True)
    LocalPort = models.CharField(max_length=500, null = True)
    ForeignAddr = models.CharField(max_length=500, null = True)
    ForeignPort = models.CharField(max_length=500, null = True)
    State = models.CharField(max_length=500, null = True)
    PID = models.BigIntegerField(null = True)
    Owner = models.CharField(max_length=500, null = True)
    Created = models.CharField(max_length=500, null = True)

class Hashdump(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )
    User = models.CharField(max_length=500, null = True)
    rid = models.BigIntegerField(null = True)
    lmhash = models.CharField(max_length=500, null = True)
    nthash = models.CharField(max_length=500, null = True)


class Lsadump(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )
    Key = models.CharField(max_length=500, null = True)
    Secret = models.CharField(max_length=1000, null = True)
    Hex = models.CharField(max_length=500, null = True)
    def save(self, *args, **kwargs):
        self.Secret = base64.b64encode(bytes(self.Secret, 'utf-8'))
        super().save(*args, **kwargs)

class Cachedump(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )
    username = models.CharField(max_length=500, null = True)
    domain = models.CharField(max_length=500, null = True)
    domain_name = models.CharField(max_length=500, null = True)
    hash = models.CharField(max_length=500, null = True)

class HiveList(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )
    FileFullPath = models.CharField(max_length=500, null = True)
    Offset = models.BigIntegerField(null = True)
    Fileoutput = models.CharField(max_length=500, null = True)

class Timeliner(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )
    Plugin = models.CharField(max_length=500, null = True)
    Description = models.CharField(max_length=500, null = True)
    AccessedDate = models.CharField(max_length=500, null = True)
    ChangedDate = models.CharField(max_length=500, null = True)
    CreatedDate = models.CharField(max_length=500, null = True)
    ModifiedDate = models.CharField(max_length=500, null = True)

class SkeletonKeyCheck(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )
    PID = models.BigIntegerField(null = True)
    Process = models.CharField(max_length=500, null = True)
    SkeletonKeyFound = models.CharField(max_length=500, null = True)
    rc4HmacInitialize = models.CharField(max_length=500, null = True)
    rc4HmacDecrypt = models.CharField(max_length=500, null = True)

class Malfind(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )

    PID = models.BigIntegerField(null = True)
    Process = models.CharField(max_length=500, null = True)
    StartVPN = models.BigIntegerField(null = True)
    EndVPN = models.BigIntegerField(null = True)
    Tag = models.CharField(max_length=500, null = True)
    Protection = models.CharField(max_length=500, null = True)
    CommitCharge = models.BigIntegerField(null = True)
    PrivateMemory = models.BigIntegerField(null = True)
    Fileoutput = models.CharField(max_length=500, null = True)
    Hexdump  = models.CharField(max_length=1000, null = True)
    Disasm = models.CharField(max_length=1000, null = True)

class FileScan(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )
    Offset = models.BigIntegerField(null = True)
    Name = models.CharField(max_length=500, null = True)
    Size = models.BigIntegerField(null = True)

class Strings(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )
    String = models.CharField(max_length=500, null = True)
    PhysicalAddress = models.BigIntegerField(null = True)
    Result = models.CharField(max_length=500, null = True)
