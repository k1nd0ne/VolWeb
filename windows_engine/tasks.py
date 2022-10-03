from investigations.celery import app
from investigations.models import UploadInvestigation
import subprocess
from .vol_windows import dump_process, dump_file


@app.task(name="dump_memory_pid")
def dump_memory_pid(case_id, pid):
    """Process dump task"""
    case = UploadInvestigation.objects.get(pk=case_id)
    dump_path = "Cases/" + case.name
    output_path = 'Cases/Results/process_dump_' + case_id
    try:
        subprocess.check_output(['mkdir', output_path])
    except:
        pass

    result = dump_process(dump_path, pid, output_path)
    if result == "Error outputting file":
        return "ERROR"
    return result


@app.task(name="dump_memory_file")
def dump_memory_file(case_id, offset):
    """Dumpfile (single file)"""
    case = UploadInvestigation.objects.get(pk=case_id)
    dump_path = "Cases/" + case.name
    data = []
    output_path = 'Cases/Results/file_dump_' + case_id
    try:
        subprocess.check_output(['mkdir', output_path])
    except:
        pass
    result = dump_file(dump_path, offset, output_path)
    if len(result) > 0:
        return result
    else:
        return "ERROR"
