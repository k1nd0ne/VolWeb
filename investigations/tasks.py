from investigations.models import *
from investigations.celery import app
from windows_engine.vol_windows import *
from linux_engine.vol_linux import *

"""Windows Memory analysis"""
def windows_memory_analysis(dump_path, case):
    partial_results = run_volweb_routine_windows(dump_path, case.id, case)
    case.percentage = "100"
    if partial_results:
        case.status = "4"
    else:
        case.status = "2"
    case.save()
    return

"""Linux Memory Analysis"""
def linux_memory_analysis(dump_path, case):
    partial_results = run_volweb_routine_linux(dump_path, case.id, case)
    case.percentage = "100"
    if partial_results:
        case.status = "4"
    else:
        case.status = "2"
    case.save()
    return

"""Main Task"""
@app.task(name="start_memory_analysis")
def start_memory_analysis(dump_path, id):
    case = UploadInvestigation.objects.get(pk=id)
    if case.os_version == "Windows":
        windows_memory_analysis(dump_path, case)
    else:
        linux_memory_analysis(dump_path, case)
