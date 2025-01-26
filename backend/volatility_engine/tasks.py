from celery import shared_task
from evidences.models import Evidence
from volatility_engine.engine import VolatilityEngine
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync


@shared_task(name="Windows.Engine")
def start_extraction(evidence_id):
    """
    This task will extract all the artefacts using different plugins
    """
    instance = Evidence.objects.get(id=evidence_id)
    engine = VolatilityEngine(instance)
    instance.status = 0
    instance.save()
    engine.start_extraction()
    if instance.status != -1:
        instance.status = 100
        instance.save()


@shared_task
def start_timeliner(evidence_id):
    """
    This task is dedicated to generate the timeline.
    We seperate this because this could take a very long time depending on the memory dump.
    """
    instance = Evidence.objects.get(id=evidence_id)
    channel_layer = get_channel_layer()
    engine = VolatilityEngine(instance)
    result = engine.start_timeliner()
    if result:
        async_to_sync(channel_layer.group_send)(
            f"volatility_tasks_{evidence_id}",
            {
                "type": "send_notification",
                "message": {
                    "name": "timeliner",
                    "status": "finished",
                    "result": "true",
                },
            },
        )
    else:
        async_to_sync(channel_layer.group_send)(
            f"volatility_tasks_{evidence_id}",
            {
                "type": "send_notification",
                "message": {
                    "name": "timeliner",
                    "status": "finished",
                    "result": "false",
                },
            },
        )


@shared_task
def dump_process(evidence_id, pid):
    """
    This task is dedicated to performing a pslist dump.
    """
    channel_layer = get_channel_layer()
    instance = Evidence.objects.get(id=evidence_id)
    engine = VolatilityEngine(instance)
    result = engine.dump_process(pid)
    async_to_sync(channel_layer.group_send)(
        f"volatility_tasks_{evidence_id}",
        {
            "type": "send_notification",
            "message": {
                "name": "dump",
                "pid": pid,
                "status": "finished",
                "result": result,
            },
        },
    )


@shared_task
def dump_windows_handles(evidence_id, pid):
    """
    This task is dedicated to compute the handles for a specific process.
    """
    instance = Evidence.objects.get(id=evidence_id)
    channel_layer = get_channel_layer()
    engine = VolatilityEngine(instance)
    engine.compute_handles(pid)
    async_to_sync(channel_layer.group_send)(
        f"volatility_tasks_{evidence_id}",
        {
            "type": "send_notification",
            "message": {
                "name": "handles",
                "pid": pid,
                "status": "finished",
                "msg": "Message",
            },
        },
    )


@shared_task
def dump_file(evidence_id, offset):
    """
    This task is dedicated for trying to dump a file at a specific memory offset.
    """
    instance = Evidence.objects.get(id=evidence_id)
    channel_layer = get_channel_layer()
    engine = VolatilityEngine(instance)
    if instance.os == "windows":
        result = engine.dump_file_windows(offset)
    else:
        result = engine.dump_file_linux(offset)
    async_to_sync(channel_layer.group_send)(
        f"volatility_tasks_{evidence_id}",
        {
            "type": "send_notification",
            "message": {
                "name": "file_dump",
                "status": "finished",
                "result": result,
            },
        },
    )


@shared_task
def dump_maps(evidence_id, pid):
    """
    This task is dedicated to compute the maps for a specific process.
    """
    instance = Evidence.objects.get(id=evidence_id)
    channel_layer = get_channel_layer()
    engine = VolatilityEngine(instance)
    result = engine.dump_process_maps(pid)
    async_to_sync(channel_layer.group_send)(
        f"volatility_tasks_{evidence_id}",
        {
            "type": "send_notification",
            "message": {
                "name": "maps",
                "pid": pid,
                "status": "finished",
                "result": result,
            },
        },
    )
