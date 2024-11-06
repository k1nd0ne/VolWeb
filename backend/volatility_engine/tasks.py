from celery import shared_task
from evidences.models import Evidence
from volatility_engine.engine import VolatilityEngine


@shared_task(name="Windows.Engine")
def start_extraction(evidence_id):
    """
    This task will extract all the artefacts using different plugins
    """
    instance = Evidence.objects.get(id=evidence_id)
    engine = VolatilityEngine(instance)
    engine.start_extraction()

@shared_task
def start_timeliner(evidence_id):
    """
    This task is dedicated to generate the timeline.
    We seperate this because this could take a very long time depending on the memory dump.
    """
    instance = Evidence.objects.get(id=evidence_id)
    engine = VolatilityEngine(instance)
    engine.start_timeliner()

@shared_task
def dump_windows_process(evidence_id, pid):
    """
    This task is dedicated to performing a pslist dump.
    """
    instance = Evidence.objects.get(id=evidence_id)
    engine = VolatilityEngine(instance)
    engine.dump_process(pid)

@shared_task
def dump_windows_handles(evidence_id, pid):
    """
    This task is dedicated to compute the handles for a specific process.
    """
    instance = Evidence.objects.get(id=evidence_id)
    engine = VolatilityEngine(instance)
    engine.compute_handles(pid)

@shared_task
def dump_windows_file(evidence_id, offset):
    """
    This task is dedicated for trying to dump a file at a specific memory offset.
    """
    instance = Evidence.objects.get(id=evidence_id)
    engine = VolatilityEngine(instance)
    engine.dump_file(offset)
