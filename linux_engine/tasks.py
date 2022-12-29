from investigations.celery import app
from investigations.models import UploadInvestigation
from .vol_linux import get_procmaps


@app.task(name="compute_procmaps")
def compute_procmaps(case_id, pid):
    """Compute Handles for a specific PID"""
    case = UploadInvestigation.objects.get(pk=case_id)
    dump_path = "Cases/" + case.name
    result = get_procmaps(dump_path, pid, case)
    return result