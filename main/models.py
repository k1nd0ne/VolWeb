from django.db import models
from django.contrib.auth.models import User
from evidences.models import Evidence

TYPES = (
    ("artifact", "Artifact"),
    ("directory", "Directory"),
    ("process", "Process"),
    ("file", "File"),
    )

TLPS = (
    ("WHITE", "WHITE"),
    ("GREEN", "GREEN"),
    ("AMBER", "AMBER"),
    ("AMBER+STRICT", "AMBER+STRICT"),
    ("RED", "RED"),
)


class Indicator(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE
    )
    type = models.CharField(max_length=100, choices=TYPES)
    description = models.TextField()
    value = models.TextField()
    tlp = models.CharField(max_length=15, choices=TLPS)
