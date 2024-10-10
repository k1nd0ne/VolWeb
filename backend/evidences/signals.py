from django.db.models.signals import post_save
from django.dispatch import receiver
from evidences.models import Evidence
from evidences.serializers import EvidenceSerializer
from evidences.tasks import start_analysis

@receiver(post_save, sender=Evidence)
def send_evidence_created(sender, instance, created, **kwargs):
    if created:
        start_analysis.apply_async(args=[instance.id])
