from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.utils.representation import serializer_repr
from evidences.models import Evidence
from evidences.tasks import start_analysis
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from evidences.serializers import EvidenceSerializer

@receiver(post_save, sender=Evidence)
def send_evidence_created(sender, instance, created, **kwargs):
    if created:
        start_analysis.delay(instance.dump_id)
    channel_layer = get_channel_layer()
    serializer = EvidenceSerializer(instance)
    async_to_sync(channel_layer.group_send)(
        "evidences",
        {"type": "send_notification", "status": "created", "message": serializer.data},
    )


@receiver(post_delete, sender=Evidence)
def send_evidence_deleted(sender, instance, **kwargs):
    channel_layer = get_channel_layer()
    serializer = EvidenceSerializer(instance)
    async_to_sync(channel_layer.group_send)(
        "evidences",
        {"type": "send_notification", "status": "deleted", "message": serializer.data},
    )
