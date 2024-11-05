from django.db.models.signals import post_save
from django.dispatch import receiver
from evidences.models import Evidence
from evidences.serializers import EvidenceSerializer
from volatility_engine.tasks import start_extraction, start_timeliner


@receiver(post_save, sender=Evidence)
def send_evidence_created(sender, instance, created, **kwargs):
    if created:
        start_extraction.apply_async(args=[instance.id])
