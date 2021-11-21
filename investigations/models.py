from django.db import models
from django.core.validators import FileExtensionValidator
class UploadInvestigation(models.Model):
    id = models.AutoField(primary_key=True)
    title = models.CharField(max_length=100)
    os_version = models.CharField(max_length=50)
    investigators = models.CharField(max_length=100)
    description = models.TextField(max_length=256)
    status = models.CharField(max_length=20)
    taskid = models.CharField(max_length=50)
    existingPath = models.CharField(unique=True, max_length=100)
    name = models.CharField(max_length=50)
    eof = models.BooleanField()
    uid = models.CharField(max_length=50)
    def __str__(self):
        return str(self.pk)

