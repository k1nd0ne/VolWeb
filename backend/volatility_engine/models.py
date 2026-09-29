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
    error_message = models.TextField(null=True, blank=True)

    def __str__(self):
        return str(self.name)


class EnrichedProcess(models.Model):
    """
    Model to store enriched process information.
    Combines data from multiple plugins for processes.
    """

    evidence = models.ForeignKey(Evidence, on_delete=models.CASCADE)
    pid = models.IntegerField()
    data = models.JSONField()

    def __str__(self):
        return str(self.pid)


class LinuxSymbolResolution(models.Model):
    """
    Tracks automatic Linux ISF (symbol table) resolution for a Linux evidence.
    Gates plugin execution: extraction is only allowed once status == "ready".
    """

    STATUS = (
        ("detecting", "Detecting banner"),
        ("resolving", "Resolving ISF"),
        ("verifying", "Verifying ISF"),
        ("ready", "Ready"),
        ("failed_banner", "Banner not found"),
        ("failed_isf", "ISF not found"),
    )
    METHODS = (
        ("remote", "Remote index"),
        ("manual", "Manual upload"),
    )

    evidence = models.OneToOneField(
        Evidence, on_delete=models.CASCADE, related_name="isf_resolution"
    )
    status = models.CharField(max_length=20, choices=STATUS, default="detecting")
    banner = models.TextField(null=True, blank=True)
    method = models.CharField(max_length=20, choices=METHODS, null=True, blank=True)
    # Manual-build guidance shown to the analyst when no ISF could be imported.
    guidance = models.JSONField(null=True, blank=True)
    message = models.TextField(null=True, blank=True)
    linked_symbol = models.ForeignKey(
        "symbols.Symbol", null=True, blank=True, on_delete=models.SET_NULL
    )
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.evidence_id}:{self.status}"
