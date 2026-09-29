from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from symbols.models import Symbol
from symbols.serializers import SymbolSerializer
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer


@receiver(post_save, sender=Symbol)
def send_symbol_created(sender, instance, created, **kwargs):
    channel_layer = get_channel_layer()
    serializer = SymbolSerializer(instance)
    async_to_sync(channel_layer.group_send)(
        "symbols",
        {"type": "send_notification", "status": "created", "message": serializer.data},
    )

    # A newly uploaded Linux ISF may satisfy evidences still waiting for symbols:
    # re-verify the ones not yet ready so the extraction gate can open.
    if created and instance.os == "Linux":
        try:
            from volatility_engine.models import LinuxSymbolResolution
            from volatility_engine.tasks import reverify_linux_symbols
            pending = LinuxSymbolResolution.objects.exclude(status="ready").values_list(
                "evidence_id", flat=True
            )
            for evidence_id in pending:
                reverify_linux_symbols.delay(evidence_id)
        except Exception:
            import logging
            logging.getLogger(__name__).exception(
                "Failed to trigger ISF re-verification after symbol upload"
            )


@receiver(post_delete, sender=Symbol)
def send_symbol_deleted(sender, instance, **kwargs):
    channel_layer = get_channel_layer()
    serializer = SymbolSerializer(instance)
    async_to_sync(channel_layer.group_send)(
        "symbols",
        {"type": "send_notification", "status": "deleted", "message": serializer.data},
    )

    # Deleting a Linux ISF may break evidences that were relying on it:
    # re-validate the currently-ready ones so the extraction gate re-closes.
    if instance.os == "Linux":
        try:
            from volatility_engine.models import LinuxSymbolResolution
            from volatility_engine.tasks import reverify_linux_symbols
            ready = LinuxSymbolResolution.objects.filter(status="ready").values_list(
                "evidence_id", flat=True
            )
            for evidence_id in ready:
                reverify_linux_symbols.delay(evidence_id)
        except Exception:
            import logging
            logging.getLogger(__name__).exception(
                "Failed to trigger ISF re-validation after symbol deletion"
            )
