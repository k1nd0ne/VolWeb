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
        related_name="macos_pstree_investigation"
    )
    graph = models.JSONField(null=True)


class PsList(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="macos_pslist_investigation"
    )
    COMM = models.TextField(null=True)
    Offset = models.BigIntegerField(null=True)
    PID = models.BigIntegerField(null=True)
    PPID = models.BigIntegerField(null=True)
    TID = models.BigIntegerField(null=True)

class Bash(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="macos_bash_investigation"
    )
    PID = models.BigIntegerField(null=True)
    Process = models.TextField(null=True)
    CommandTime = models.TextField(null=True)
    Command = models.CharField(max_length=500, null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)