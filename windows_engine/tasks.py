from celery import shared_task
from windows_engine.vol_windows import get_handles
from evidences.models import Evidence
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync


@shared_task(bind=True)
def compute_handles(self, evidence_id, pid):
    channel_layer = get_channel_layer()
    instance = Evidence.objects.get(dump_id=evidence_id)
    result = get_handles(instance, pid)
    if result:
        async_to_sync(channel_layer.group_send)(
            f"volatility_tasks_{evidence_id}",
            {
                "type": "send_notification",
                "message": {
                    "name": "handles",
                    "pid": pid,
                    "status": "success",
                    "msg": f"Handles for PID {pid} are now available.",
                },
            },
        )
    else:
        async_to_sync(channel_layer.group_send)(
            f"volatility_tasks_{evidence_id}",
            {
                "type": "send_notification",
                "message": {
                    "name": "handles",
                    "pid": pid,
                    "status": "success",
                    "msg": f"Handle computation for PID {pid} failed.",
                },
            },
        )
    return {"name":"handles", "PID":pid,"evidence": evidence_id}
