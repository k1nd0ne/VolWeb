from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from cases.models import Case
from cases.serializers import CaseSerializer
from volatility_engine.tasks import start_extraction, start_timeliner
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

@receiver(post_save, sender=Case)
def send_case_created(sender, instance, created, **kwargs):
    channel_layer = get_channel_layer()
    serializer = CaseSerializer(instance)
    async_to_sync(channel_layer.group_send)(
        "cases",
        {"type": "send_notification", "status": "created", "message": serializer.data},
    )


@receiver(
    post_delete,
    sender=Case,
)
def send_case_deleted(sender, instance, **kwargs):
    channel_layer = get_channel_layer()
    serializer = CaseSerializer(instance)
    async_to_sync(channel_layer.group_send)(
        "cases",
        {"type": "send_notification", "status": "deleted", "message": serializer.data},
    )
