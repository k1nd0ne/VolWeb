from django.db import models

#OS CHOICE
CHOICES = (
        ('Windows', 'Windows'),
#        ('Linux', 'Linux'), <- not implemented yet
#        ('MacOs', 'MacOs'), <- not implemented yet
    )

class UploadInvestigation(models.Model):
    id = models.AutoField(primary_key=True)
    title = models.CharField(max_length=255)
    os_version = models.CharField(max_length=50, choices = CHOICES)
    investigators = models.CharField(max_length=255)
    description = models.TextField(max_length=255)
    status = models.CharField(max_length=20)
    percentage = models.CharField(max_length=10)
    taskid = models.CharField(max_length=255)
    existingPath = models.CharField(unique=True, max_length=255)
    name = models.CharField(max_length=255)
    eof = models.BooleanField()
    uid = models.CharField(max_length=255)
    def __str__(self):
        return str(self.title)

class Activity(models.Model):
    date = models.DateField(primary_key=True)
    count = models.IntegerField()


class ProcessDump(models.Model):
    process_dump_id = models.AutoField(primary_key=True)
    case_id = models.ForeignKey(
        'UploadInvestigation',
        on_delete=models.CASCADE,
    )
    pid = models.IntegerField()
    filename = models.CharField(max_length = 255)

class FileDump(models.Model):
    file_dump_id = models.AutoField(primary_key=True)
    case_id = models.ForeignKey(
        'UploadInvestigation',
        on_delete=models.CASCADE,
    )
    offset = models.IntegerField()
    filename = models.CharField(max_length = 255)
