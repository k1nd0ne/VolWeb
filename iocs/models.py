from django.db import models

class NewIOC(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=50)
    value = models.CharField(max_length=100)
    linkedInvestigation = models.CharField(max_length=100)
    linkedInvestigationID = models.CharField(max_length=100)
    def __str__(self):
        return str(self.pk)
