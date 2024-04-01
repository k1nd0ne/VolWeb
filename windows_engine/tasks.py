from celery import shared_task
from volatility3.framework.renderers import datetime
from evidences.models import Evidence
from windows_engine.models import PsTree
from windows_engine.models import Loot, FileScan, Handles
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from django.forms.models import model_to_dict
import datetime


@shared_task
def compute_handles(evidence_id, pid):
    channel_layer = get_channel_layer()
    instance = Evidence.objects.get(dump_id=evidence_id)
    result = Handles(evidence=instance).run(pid)
    status = "success" if result else "error"
    msg = (
        f"Handles for PID {pid} are now available."
        if result
        else f"Handle computation for PID {pid} failed."
    )
    async_to_sync(channel_layer.group_send)(
        f"volatility_tasks_{evidence_id}",
        {
            "type": "send_notification",
            "message": {
                "name": "handles",
                "pid": pid,
                "status": status,
                "msg": msg,
            },
        },
    )


@shared_task
def dump_process_pslist(evidence_id, pid):
    channel_layer = get_channel_layer()
    instance = PsTree.objects.get(evidence_id=evidence_id)
    result = instance.pslist_dump(pid)
    loot = Loot(
        evidence=instance.evidence,
        FileName=result if result != "Error outputting file" else "No Result",
        Date=datetime.datetime.now().isoformat(),
        Status=result != "Error outputting file",
        Name=f"Process with PID {pid} - FileName: {result} - Dumped using PsList."
        if result != "Error outputting file"
        else f"Process with PID {pid} - Result: {result} - Dumped using PsList.",
    )
    loot.save()
    data = model_to_dict(loot)
    data["Date"] = loot.Date.isoformat()
    async_to_sync(channel_layer.group_send)(
        f"volatility_tasks_{evidence_id}",
        {
            "type": "send_notification",
            "message": {
                "name": "pslist_dump",
                "pid": pid,
                "status": "success" if loot.Status else "error",
                "msg": data,
            },
        },
    )


@shared_task
def dump_process_memmap(evidence_id, pid):
    channel_layer = get_channel_layer()
    instance = PsTree.objects.get(evidence_id=evidence_id)
    result = instance.memmap_dump(pid)
    loot = Loot(
        evidence=instance.evidence,
        FileName=result,
        Date=datetime.datetime.now().isoformat(),
        Name=f"Process with PID {pid} - FileName: {result} - Dumped using Memmap.",
        Status=result != "Error outputting file",
    )
    loot.save()
    data = model_to_dict(loot)
    data["Date"] = loot.Date.isoformat()
    status = "success" if loot.Status else "error"
    async_to_sync(channel_layer.group_send)(
        f"volatility_tasks_{evidence_id}",
        {
            "type": "send_notification",
            "message": {
                "name": "memmap_dump",
                "pid": pid,
                "status": status,
                "msg": data,
            },
        },
    )


@shared_task
def dump_file(evidence_id, offset):
    channel_layer = get_channel_layer()
    instance = Evidence.objects.get(dump_id=evidence_id)
    try:
        file_obj = FileScan.objects.get(evidence_id=evidence_id)
        filename = next(
            (d["Name"] for d in file_obj.artefacts if d["Offset"] == offset), None
        )
        result = file_obj.file_dump(offset)
        if not result:
            raise ValueError("File dump failed (data not available)")

        for file in result:
            loot = Loot(evidence=instance, Date=datetime.datetime.now().isoformat())
            if file["Result"] != "Error dumping file":
                loot.Name = f"File {filename} - found in {file['Cache']} and dumped as {file['FileName']}."
                loot.Status = True
                loot.FileName = file["Result"]
            else:
                loot.Name = f"File {filename} - not found in {file['Cache']}."
                loot.Status = False
                loot.FileName = file["Result"]
            loot.save()
            data = model_to_dict(loot)
            data["Date"] = loot.Date.isoformat()
            async_to_sync(channel_layer.group_send)(
                f"volatility_tasks_{evidence_id}",
                {
                    "type": "send_notification",
                    "message": {
                        "name": "file_dump",
                        "status": "success" if loot.Status else "failed",
                        "msg": data,
                    },
                },
            )
    except Exception as e:
        async_to_sync(channel_layer.group_send)(
            f"volatility_tasks_{evidence_id}",
            {
                "type": "send_notification",
                "message": {
                    "name": "file_dump",
                    "status": "error",
                    "msg": str(e) or "The file you are trying to dump doesn't exist.",
                },
            },
        )
