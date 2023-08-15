from django.db import models
from django.contrib.auth.models import User

OS = (
    ('Windows', 'Windows'),
    ('Linux', 'Linux'),
#   ('MacOs', 'MacOs'), <- not implemented yet
)

class Case(models.Model):
    case_id = models.AutoField(primary_key=True)
    case_name = models.CharField(max_length=500)
    case_description = models.TextField()
    linked_users = models.ManyToManyField(User)
    case_last_update = models.DateField(auto_now=True)
    def __str__(self):
        return self.case_name
   

class MemoryDump(models.Model):
    dump_id = models.AutoField(primary_key=True)
    dump_name = models.CharField(max_length=250)
    dump_os = models.CharField(max_length=10, choices=OS)
    dump_linked_case = models.ForeignKey(
        Case,
        on_delete=models.CASCADE,
        null=True
    )
    def __str__(self):
        return str(self.dump_name)
   
class ImageSignature(models.Model):
    investigation = models.ForeignKey(
        Case,
        on_delete=models.CASCADE,
    )
    md5 = models.CharField(max_length=32, null=True)
    sha1 = models.CharField(max_length=40, null=True)
    sha256 = models.CharField(max_length=64, null=True)




