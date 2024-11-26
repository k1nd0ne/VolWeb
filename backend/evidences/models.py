from django.db import models
from cases.models import Case

OS = (
    ("windows", "windows"),
    ("linux", "linux"),
    #   ('MacOs', 'MacOs'), <- not implemented yet
)

SOURCES = (
    ("AWS", "AWS"),
    ("MINIO", "MINIO"),
    ("FILESYSTEM", "FILESYSTEM"),
)


class Evidence(models.Model):
    """
    Evidence Model
    Holds the important metadata about the memory image.
    """

    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=250)
    etag = models.CharField(max_length=256, unique=True)
    os = models.CharField(max_length=10, choices=OS)
    linked_case = models.ForeignKey(Case, on_delete=models.CASCADE, null=False)
    status = models.IntegerField(default=0)
    access_key_id = models.TextField(null=True)
    access_key = models.TextField(null=True)
    url = models.TextField(null=True)
    region = models.TextField(null=True)
    endpoint = models.TextField(null=True)
    source = models.CharField(max_length=10, choices=SOURCES, null=True)

    def __str__(self):
        return str(self.name)
