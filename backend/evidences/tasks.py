from celery import shared_task
from evidences.models import Evidence
from volatility_engine.engine import VolatiltiyEngine


@shared_task(name="Windows.Engine")
def start_extraction(evidence_id):
    """
    This task will extract all the artefacts using different plugins
    """
    instance = Evidence.objects.get(id=evidence_id)
    if instance.os == "windows":
        # Start the Windows Artefact extraction
        engine = VolatiltiyEngine(instance)
        engine.start_extraction()
    else:
        print("LINUX ENGINE START")


def start_timeliner(evidence_id):
    """
    This task is dedicated to generate the timeline.
    We seperate this because this could take a very long time
    """
    instance = Evidence.objects.get(id=evidence_id)
    evidence_data = get_evidence_context(instance)
    print("TIMELINER START")
