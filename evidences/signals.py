from django.db.models.signals import post_save
from django.dispatch import receiver
from evidences.models import Evidence
from evidences.tasks import start_analysis
import os


# When an evidence is uploaded, the analysis starts automatically.
@receiver(post_save, sender=Evidence)
def trigger_celery_task(sender, instance, created, **kwargs):
    if created:
        start_analysis.delay(instance.dump_id)
