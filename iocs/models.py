from django.db import models
from investigations.models import UploadInvestigation


class IOC(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    context = models.CharField(max_length=255)
    value = models.CharField(max_length=255)
    linkedInvestigation = models.ForeignKey(UploadInvestigation, on_delete=models.CASCADE)

    def __str__(self):
        return str(self.pk)
