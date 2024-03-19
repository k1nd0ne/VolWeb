from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.utils.representation import serializer_repr
from evidences.models import Evidence
from evidences.tasks import start_analysis
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from django.db.models.signals import post_save, post_delete
from evidences.serializers import EvidenceSerializer
from celery import states
from celery.signals import before_task_publish
from django_celery_results.models import TaskResult
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token


@receiver(post_save, sender=User)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)


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


@before_task_publish.connect
def create_task_result_on_publish(sender=None, headers=None, body=None, **kwargs):
    if "task" not in headers:
        return

    TaskResult.objects.store_result(
        "application/json",
        "utf-8",
        headers["id"],
        None,
        states.PENDING,
        task_name=headers["task"],
        task_args=headers["argsrepr"],
        task_kwargs=headers["kwargsrepr"],
    )
