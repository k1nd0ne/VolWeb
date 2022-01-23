from .models import *
from iocs.models import NewIOC
from .celery import app
from json import dumps
import subprocess, time, json, re, os
from .vol_windows import *
from .vol_linux import *

"""
Process dump task
"""
@app.task(name="dump_memory_pid")
def dump_memory_pid(case_id,pid):
    case = UploadInvestigation.objects.get(pk=case_id)
    dump_path = "Cases/" + case.name
    data = []
    try:
        output = subprocess.check_output(['vol', '-r', 'json', '-f', str(dump_path), '-o', 'Cases/Results/', 'windows.pslist', '--pid', pid, '--dump'])
        dump_info = output.decode()
        raw_data = json.loads(dump_info)
        data = {k.replace(" ", "_"): v for k, v in raw_data[0].items()}
        return data['File_output']
    except:
        print("Error processing memory dump ")
        return "ERROR"


"""
Dumpfile (single file)
"""
@app.task(name="dump_memory_file")
def dump_memory_file(case_id, offset):
    case = UploadInvestigation.objects.get(pk=case_id)
    dump_path = "Cases/" + case.name
    data = []
    try:
        output = subprocess.check_output(['vol', '-r', 'json', '-f', str(dump_path), '-o', 'Cases/Results/', 'windows.dumpfiles', '--physaddr', hex(offset)])
        filedump_info = output.decode()
        data = json.loads(filedump_info)
        return data[0]['Result']
    except subprocess.CalledProcessError as err:
        print('Error processing memory dump: ',err)
        return "ERROR"



"""
Build Timeline
"""
def build_timeline(data):
    timeline = []
    nb_event = 1
    actual_date = ""
    try:
        saved_date = data[0]["Created Date"]
    except:
        print("Timeline Error")
        return
    for i in data:
        try:
            actual_date = str(i["Created Date"])
            if actual_date != saved_date:
                timeline.append([saved_date,nb_event])
                saved_date = actual_date
                nb_event = 1
            else:
                nb_event+=1
        except:
            print("timeline error")
            return
    return {"linechart": dumps(timeline)}

"""
Dump Timeline
"""
def collect_image_timeline(dump_path):
     data = []
     try:
         output = subprocess.check_output(['vol', '-r','json', '-f', dump_path, 'timeliner.Timeliner'])
     except subprocess.CalledProcessError as err:
         print("Error processing memory dump: ", err)
         return {'timeline': ['no data']}
     timeline_info = output.decode()
     data = json.loads(timeline_info)
     return {'timeline': data}


"""
Windows automatic analysis
"""
def windows_memory_analysis(dump_path,case):
    #Collect IOCs with the strings utility
    iocs = NewIOC.objects.all()
    terms = ""
    ioc_result_name = "Cases/IOCs/iocs_invest_" + str(case.id)
    strings_output_file = "Cases/IOCs/output_"+ str(case.id)

    with open(ioc_result_name, 'w') as fout:
        fout.write('')
        fout.close()

    for ioc in iocs:
        if (str(case.id) in ioc.linkedInvestigationID) or ('-1' in ioc.linkedInvestigationID):
            terms = terms + ioc.value + "|"
    if terms != "":
        with open(strings_output_file, 'w') as fout:
            fout.write(subprocess.check_output(['strings', '-t', 'd', dump_path]).decode())
        with open(ioc_result_name, 'w') as fout:
            fout.write(subprocess.check_output(['grep', '-E', terms[:len(terms)-1] ,  strings_output_file]).decode())
    f_len = os.path.getsize(ioc_result_name)
    if f_len <= 1:
        iocmatch = {'iocmatch':[['No IOCs']]}
    else:
        iocmatch = collect_user_iocs(dump_path,ioc_result_name)

    # Run volatility modules and get the results
    malwarefind = malfind(dump_path)
    hashdump = collect_image_hash(dump_path)
    filescan = collect_image_files(dump_path)
    timeline = collect_image_timeline(dump_path)
    timeline_chart = build_timeline(timeline['timeline'])
    pstree = collect_image_pstree(dump_path)
    graph = build_graph(pstree['pstree'])
    netscan = collect_image_netscan(dump_path)
    netstat = collect_image_netstat(dump_path)
    netgraph = generate_network_graph(netscan['netscan'] + netstat['netstat'])
    psscan = collect_image_psscan(dump_path)
    cmdline = collect_image_cmdline(dump_path)
    privileges = collect_image_privileges(dump_path)
    env = collect_image_env(dump_path)
    skeleton = skc(dump_path)
    lsadump = lsa_dump(dump_path)
    cachedump = cache_dump(dump_path)

    #Save the result to json
    results = { **malwarefind, **pstree, **psscan,
              **netscan, **netstat, **netgraph,
              **graph, **cmdline, **privileges,
              **env, **timeline, **timeline_chart,
              **filescan, **hashdump, **iocmatch, **skeleton,
              **lsadump, **cachedump }

    with open('Cases/Results/'+str(case.id)+'.json', 'w') as json_file:
        json.dump(results, json_file)

    #Update the case status
    case.status = "2"
    case.save()
    return

def linux_memory_analysis(dump_path, case):
    timeline = collect_image_timeline(dump_path)
    timeline_chart = build_timeline(timeline['timeline'])
    with open('Cases/Results/'+str(case.id)+'.json', 'w') as json_file:
        json.dump(results, json_file)
    #Update the case status
    case.status = "2"
    case.save()
    return

"""
Main task :
- Detect the OS
- Launch each volatility modules and save the result into a json file
"""

"""
OS Detection :
"""
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


@app.task(name="start_memory_analysis")
def start_memory_analysis(dump_path,id):
    case = UploadInvestigation.objects.get(pk=id)
    operating_system = os_detection(dump_path)
    if operating_system == -1:
        print("Error Getting The OS Version")
    elif operating_system > 0:
        print("OS Detected as Linux")
        linux_memory_analysis(dump_path,case)
    else:
        print("OS detected as Windows")
        windows_memory_analysis(dump_path,case)
