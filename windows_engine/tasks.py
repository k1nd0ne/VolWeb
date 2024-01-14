from celery import shared_task
from windows_engine.vol_windows import get_handles, pslist_dump, memmap_dump
from evidences.models import Evidence
from windows_engine.models import Loot
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
                    "status": "error",
                    "msg": f"Handle computation for PID {pid} failed.",
                },
            },
        )


@shared_task(bind=True)
def dump_process_pslist(self, evidence_id, pid):
    channel_layer = get_channel_layer()
    instance = Evidence.objects.get(dump_id=evidence_id)
    result = pslist_dump(instance, pid)
    loot = Loot()
    loot.evidence = instance
    if result != "Error outputting file":
        loot.Status = True
        loot.Name = f"Process with PID {pid} - FileName: {result} - Dumped using PsList."
        loot.FileName = result
        async_to_sync(channel_layer.group_send)(
            f"volatility_tasks_{evidence_id}",
            {
                "type": "send_notification",
                "message": {
                    "name": "pslist_dump",
                    "pid": pid,
                    "status": "success",
                    "msg": f"Process dump for PID {pid} is a success.",
                },
            },
        )
    else:
        loot.Status = False
        loot.Name = f"Process with PID {pid} - Result: {result} - Dumped using PsList"
        loot.FileName = result
        async_to_sync(channel_layer.group_send)(
            f"volatility_tasks_{evidence_id}",
            {
                "type": "send_notification",
                "message": {
                    "name": "pslist_dump",
                    "pid": pid,
                    "status": "error",
                    "msg": f"Process dump for PID {pid} failed.",
                },
            },
        )
    loot.save()


@shared_task(bind=True)
def dump_process_memmap(self, evidence_id, pid):
    channel_layer = get_channel_layer()
    instance = Evidence.objects.get(dump_id=evidence_id)
    result = memmap_dump(instance, pid)
    loot = Loot()
    loot.evidence = instance
    if result != "Error outputting file":
        loot.Name = f"Process with PID {pid} - FileName: {result} - Dumped using Memmap."
        loot.Status = True
        loot.FileName = result
        async_to_sync(channel_layer.group_send)(
            f"volatility_tasks_{evidence_id}",
            {
                "type": "send_notification",
                "message": {
                    "name": "memmap_dump",
                    "pid": pid,
                    "status": "success",
                    "msg": f"Process dump for PID {pid} is a success.",
                },
            },
        )
    else:
        loot.Status = False
        loot.Name = f"Process with PID {pid} - Result: {result} - Dumped using Memmap"
        loot.FileName = result
        async_to_sync(channel_layer.group_send)(
            f"volatility_tasks_{evidence_id}",
            {
                "type": "send_notification",
                "message": {
                    "name": "memmap_dump",
                    "pid": pid,
                    "status": "error",
                    "msg": f"Process dump for PID {pid} failed.",
                },
            },
        )
    loot.save()
