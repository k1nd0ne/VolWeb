from rest_framework import serializers
from evidences.models import Evidence
from cases.models import Case
from django.dispatch import receiver
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from django.db.models.signals import post_save, post_delete


class EvidenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Evidence
        fields = "__all__"


@receiver(post_save, sender=Evidence)
def send_case_created(sender, instance, created, **kwargs):
    channel_layer = get_channel_layer()
    serializer = EvidenceSerializer(instance)
    async_to_sync(channel_layer.group_send)(
        "evidences",
        {"type": "send_notification", "status": "created", "message": serializer.data},
    )


@receiver(post_delete, sender=Evidence)
def send_case_created(sender, instance, **kwargs):
    channel_layer = get_channel_layer()
    serializer = EvidenceSerializer(instance)
    async_to_sync(channel_layer.group_send)(
        "evidences",
        {"type": "send_notification", "status": "deleted", "message": serializer.data},
    )
