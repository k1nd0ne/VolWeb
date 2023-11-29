from celery import shared_task
from windows_engine.vol_windows import get_handles
from evidences.models import Evidence

@shared_task
def compute_handles(evidence_id, pid):
        instance = Evidence.objects.get(dump_id=evidence_id)
        print("GO FOR HANDLES")
        get_handles(instance, pid)