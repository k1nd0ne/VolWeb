from rest_framework import serializers
from symbols.models import Symbol
from django.contrib.auth.models import User
from django.dispatch import receiver
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from django.db.models.signals import post_save, post_delete

class SymbolSerializer(serializers.ModelSerializer):
    class Meta:
        model = Symbol
        fields = "__all__"

@receiver(post_save, sender=Symbol)
def send_symbol_created(sender, instance, created, **kwargs):
    channel_layer = get_channel_layer()
    serializer = SymbolSerializer(instance)
    async_to_sync(channel_layer.group_send)(
        "symbols",
        {"type": "send_notification", "status": "created", "message": serializer.data},
    )


@receiver(post_delete, sender=Symbol)
def send_symbol_created(sender, instance, **kwargs):
    channel_layer = get_channel_layer()
    serializer = SymbolSerializer(instance)
    async_to_sync(channel_layer.group_send)(
        "symbols",
        {"type": "send_notification", "status": "deleted", "message": serializer.data},
    )
