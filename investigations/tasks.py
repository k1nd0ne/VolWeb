from .models import *
from iocs.models import IOC
from .celery import app
from .vol_windows import *
"""Process dump task"""
@app.task(name="dump_memory_pid")
def dump_memory_pid(case_id,pid):
    case = UploadInvestigation.objects.get(pk=case_id)
    dump_path = "Cases/" + case.name
    output_path = 'Cases/Results/process_dump_'+case_id
    try:
        subprocess.check_output(['mkdir', output_path])
    except:
        pass
    try:
        result = dump_process(dump_path, pid, output_path)
        return result
    except:
        print("Error processing memory dump ")
        return "ERROR"

@app.task(name="clamav_file")
def clamav_file(filepath):
    try:
        output = subprocess.check_output(['clamdscan', '-v','--fdpass', '--stream', filepath],timeout=120)
        return (False,"")
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            return (True,e.output.decode().splitlines()[0].split(" ")[1])
        elif e.returncode == 2:
            return (True,"Unable to check for viruses")

    except Exception as e:
        return (True,"Unable to check for viruses. Unknown Error")
    

"""Dumpfile (single file)"""
@app.task(name="dump_memory_file")
def dump_memory_file(case_id, offset):
    case = UploadInvestigation.objects.get(pk=case_id)
    dump_path = "Cases/" + case.name
    data = []
    output_path = 'Cases/Results/file_dump_'+case_id
    try:
        subprocess.check_output(['mkdir', output_path])
    except:
        pass
    result = dump_file(dump_path, offset, output_path)
    logger.info(f"Result : {result}")
    return result

"""Windows automatic analysis"""
def windows_memory_analysis(dump_path,case):
    PARTIAL_RESULTS = run_volweb_routine(dump_path,case.id,case)
    case.percentage = "100"
    if PARTIAL_RESULTS:
        case.status = "4"
    else:
        case.status = "2"
    case.save()
    return

"""Linux Memory Analysis (Not implemented yet)"""
def linux_memory_analysis(dump_path, case):
    timeline = collect_image_timeline(dump_path)
    timeline_chart = build_timeline(timeline['timeline'])
    with open('Cases/Results/'+str(case.id)+'.json', 'w') as json_file:
        json.dump(results, json_file)
    #Update the case status
    case.status = "2"
    case.save()
    return

"""OS Detection"""
def os_detection(dump_path):
    data = []
    try:
        output = subprocess.check_output(['vol', '-r', 'json', '-f', dump_path, 'banners'])
    except subprocess.CalledProcessError as err:
        print("Error processing memory dump: ", err)
        return -1
    strings_info = output.decode()
    data = json.loads(strings_info)
    return len(data)

"""Main Task"""
@app.task(name="start_memory_analysis")
def start_memory_analysis(dump_path,id):
    case = UploadInvestigation.objects.get(pk=id)
    windows_memory_analysis(dump_path,case)
