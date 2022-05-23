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
    Process = models.TextField(null = True)
    Args = models.TextField(null = True)


class Privs(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )
    PID = models.BigIntegerField(null = True)
    Process = models.TextField(null = True)
    Value = models.BigIntegerField(null = True)
    Privilege = models.TextField(null = True)
    Attributes = models.TextField(null = True)
    Description = models.TextField(null = True)

class Envars(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )
    PID = models.BigIntegerField(null = True)
    Process = models.TextField(null = True)
    Block = models.TextField(null = True)
    Variable = models.TextField(null = True)
    Value = models.TextField(null = True)
    Description = models.TextField(null = True)


class NetScan(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )
    Offset = models.BigIntegerField(null = True)
    Proto = models.TextField(null = True)
    LocalAddr = models.TextField(null = True)
    LocalPort = models.TextField(null = True)
    ForeignAddr = models.TextField(null = True)
    ForeignPort = models.TextField(null = True)
    State = models.TextField(null = True)
    PID = models.BigIntegerField(null = True)
    Owner = models.TextField(null = True)
    Created = models.TextField(null = True)

class NetStat(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )
    Offset = models.BigIntegerField(null = True)
    Proto = models.TextField(null = True)
    LocalAddr = models.TextField(null = True)
    LocalPort = models.TextField(null = True)
    ForeignAddr = models.TextField(null = True)
    ForeignPort = models.TextField(null = True)
    State = models.TextField(null = True)
    PID = models.BigIntegerField(null = True)
    Owner = models.TextField(null = True)
    Created = models.TextField(null = True)

class Hashdump(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )
    User = models.TextField(null = True)
    rid = models.BigIntegerField(null = True)
    lmhash = models.TextField(null = True)
    nthash = models.TextField(null = True)


class Lsadump(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )
    Key = models.TextField(null = True)
    Secret = models.TextField(null = True)
    Hex = models.TextField(null = True)
    def save(self, *args, **kwargs):
        self.Secret = base64.b64encode(bytes(self.Secret, 'utf-8'))
        super().save(*args, **kwargs)

class Cachedump(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )
    username = models.TextField(null = True)
    domain = models.TextField(null = True)
    domain_name = models.TextField(null = True)
    hash = models.TextField(null = True)

class HiveList(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )
    FileFullPath = models.TextField(null = True)
    Offset = models.BigIntegerField(null = True)
    Fileoutput = models.TextField(null = True)

class Timeliner(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )
    Plugin = models.TextField(null = True)
    Description = models.TextField(null = True)
    AccessedDate = models.TextField(null = True)
    ChangedDate = models.TextField(null = True)
    CreatedDate = models.TextField(null = True)
    ModifiedDate = models.TextField(null = True)

class SkeletonKeyCheck(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )
    PID = models.BigIntegerField(null = True)
    Process = models.TextField(null = True)
    SkeletonKeyFound = models.TextField(null = True)
    rc4HmacInitialize = models.TextField(null = True)
    rc4HmacDecrypt = models.TextField(null = True)

class Malfind(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )

    PID = models.BigIntegerField(null = True)
    Process = models.TextField(null = True)
    StartVPN = models.BigIntegerField(null = True)
    EndVPN = models.BigIntegerField(null = True)
    Tag = models.TextField(null = True)
    Protection = models.TextField(null = True)
    CommitCharge = models.BigIntegerField(null = True)
    PrivateMemory = models.BigIntegerField(null = True)
    Fileoutput = models.TextField(null = True)
    Hexdump  = models.TextField(null = True)
    Disasm = models.TextField(null = True)

class FileScan(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )
    Offset = models.BigIntegerField(null = True)
    Name = models.TextField(null = True)
    Size = models.BigIntegerField(null = True)

class Strings(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
        )
    String = models.TextField(null = True)
    PhysicalAddress = models.BigIntegerField(null = True)
    Result = models.TextField(null = True)
