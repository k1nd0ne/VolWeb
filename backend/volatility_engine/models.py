from django.db import models
from evidences.models import Evidence


class VolatilityPlugin(models.Model):
    """
    Django model of a volatility3 plugin
    Each plugin as a name a linked evidence and the extracted artefacts
    """

    name = models.CharField(max_length=100)
    icon = models.CharField(max_length=30, null=True)
    description = models.TextField(null=True)
    evidence = models.ForeignKey(Evidence, on_delete=models.CASCADE)
    artefacts = models.JSONField(null=True)
    category = models.CharField(max_length=100)
    display = models.CharField(max_length=10)
    results = models.BooleanField(default=False)

    def __str__(self):
        return str(self.name)
