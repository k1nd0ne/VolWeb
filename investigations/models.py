from django.db import models
from symbols.models import Symbols
import datetime, base64

# OS CHOICE
CHOICES = (
    ('Windows', 'Windows'),
    ('Linux', 'Linux'),
    ('MacOs', 'MacOs')
)


class UploadInvestigation(models.Model):
    id = models.AutoField(primary_key=True)
    linked_isf = models.ForeignKey(
        Symbols,
        on_delete=models.SET_NULL,
        null=True
    )
    title = models.CharField(max_length=500)
    os_version = models.CharField(max_length=50, choices=CHOICES)
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
    md5 = models.CharField(max_length=32, null=True)
    sha1 = models.CharField(max_length=40, null=True)
    sha256 = models.CharField(max_length=64, null=True)
