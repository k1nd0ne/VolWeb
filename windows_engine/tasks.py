from celery import shared_task
from evidences.models import Evidence
from windows_engine.models import PsTree
from windows_engine.models import Loot, FileScan, Handles
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from django.forms.models import model_to_dict
import json

@shared_task
def compute_handles(evidence_id, pid):
    channel_layer = get_channel_layer()
    instance = Evidence.objects.get(dump_id=evidence_id)
    result = Handles(evidence = instance).run(pid)
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


@shared_task
def dump_process_pslist(evidence_id, pid):
    channel_layer = get_channel_layer()
    instance = PsTree.objects.get(evidence_id=evidence_id)
    result = instance.pslist_dump(pid)
    loot = Loot()
    loot.evidence = instance.evidence
    if result != "Error outputting file":
        loot.Status = True
        loot.Name = f"Process with PID {pid} - FileName: {result} - Dumped using PsList."
        loot.FileName = result
        loot.save()
        async_to_sync(channel_layer.group_send)(
            f"volatility_tasks_{evidence_id}",
            {
                "type": "send_notification",
                "message": {
                    "name": "pslist_dump",
                    "pid": pid,
                    "status": "success",
                    "msg": json.dumps(model_to_dict(loot)),
                },
            },
        )
    else:
        loot.Status = False
        loot.Name = f"Process with PID {pid} - Result: {result} - Dumped using PsList."
        loot.FileName = result
        loot.save()
        async_to_sync(channel_layer.group_send)(
            f"volatility_tasks_{evidence_id}",
            {
                "type": "send_notification",
                "message": {
                    "name": "pslist_dump",
                    "pid": pid,
                    "status": "error",
                    "msg": json.dumps(model_to_dict(loot)),
                },
            },
        )

@shared_task(bind=True)
def dump_process_memmap(self, evidence_id, pid):
    channel_layer = get_channel_layer()
    instance = PsTree.objects.get(evidence_id=evidence_id)
    result = instance.memmap_dump(pid)
    loot = Loot()
    loot.evidence = instance.evidence
    if result != "Error outputting file":
        loot.Name = f"Process with PID {pid} - FileName: {result} - Dumped using Memmap."
        loot.Status = True
        loot.FileName = result
        loot.save()
        async_to_sync(channel_layer.group_send)(
            f"volatility_tasks_{evidence_id}",
            {
                "type": "send_notification",
                "message": {
                    "name": "memmap_dump",
                    "pid": pid,
                    "status": "success",
                    "msg": json.dumps(model_to_dict(loot)),
                },
            },
        )
    else:
        loot.Status = False
        loot.Name = f"Process with PID {pid} - Result: {result} - Dumped using Memmap."
        loot.FileName = result
        loot.save()
        async_to_sync(channel_layer.group_send)(
            f"volatility_tasks_{evidence_id}",
            {
                "type": "send_notification",
                "message": {
                    "name": "memmap_dump",
                    "pid": pid,
                    "status": "error",
                    "msg": json.dumps(model_to_dict(loot)),
                },
            },
        )

@shared_task(bind=True)
def dump_file(self, evidence_id, offset):
    channel_layer = get_channel_layer()
    instance = Evidence.objects.get(dump_id=evidence_id)
    try:
        file_obj = FileScan.objects.get(evidence_id=evidence_id)
        filename = [d for d in file_obj.artefacts if d['Offset'] == offset][0]['Name']
        result = file_obj.file_dump(offset)
        if result:
            for file in result:
                loot = Loot()
                loot.evidence = instance
                loot.Name = f"File {filename} - found in {file['Cache']} and dumped as {file['FileName']}."
                loot.Status = True
                loot.FileName = file['Result']
                loot.save()
                async_to_sync(channel_layer.group_send)(
                    f"volatility_tasks_{evidence_id}",
                    {
                        "type": "send_notification",
                        "message": {
                            "name": "file_dump",
                            "status": "success",
                            "msg": json.dumps(model_to_dict(loot)),
                        },
                    },
                )
        else:
            loot = Loot()
            loot.Status = False
            loot.evidence = instance
            loot.Name = f"File {filename} - Dump failed (data not available)."
            loot.FileName = result
            loot.save()
            async_to_sync(channel_layer.group_send)(
                f"volatility_tasks_{evidence_id}",
                {
                    "type": "send_notification",
                    "message": {
                        "name": "file_dump",
                        "status": "failed",
                        "msg": json.dumps(model_to_dict(loot)),
                    },
                },
            )
    except:
        async_to_sync(channel_layer.group_send)(
            f"volatility_tasks_{evidence_id}",
            {
                "type": "send_notification",
                "message": {
                    "name": "file_dump",
                    "status": "error",
                    "msg": "The file you are trying to dump doesn't exist.",
                },
            },
        )
