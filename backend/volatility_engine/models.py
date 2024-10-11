from django.db import models
from evidences.models import Evidence


class VolatilityPlugin(models.Model):
    """
    Django model of a volatility3 plugin
    Each plugin as a name a linked evidence and the extracted artefacts
    """

    name = models.CharField(max_length=100)
    evidence = models.ForeignKey(Evidence, on_delete=models.CASCADE)
    artefacts = models.JSONField(null=True)
