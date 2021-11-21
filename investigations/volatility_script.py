#!/usr/bin/python3
import subprocess
import re
import os
import json
from json import dumps
from .models import UploadInvestigation
from iocs.models import NewIOC

#Global Context variable
context = {}

"""
Process IOC Extraction
"""
def collect_user_iocs(dump_path,investigation_ioc_path):
    data = []
    try:
        output = subprocess.check_output(['vol', '-f' ,dump_path, 'windows.strings' ,'--strings-file', investigation_ioc_path])
    except subprocess.CalledProcessError as err:
        print("Error processing memory dump: ", err)
        return {'iocmatch':[['Nothing Found']]}
    strings_info = output.splitlines()
    for elem in strings_info[4:]:
        data.append(list(filter(None,elem.decode("utf-8").split('\t'))))
    data = data[4:]
    result = data = [i+j for i, j in zip(data[::2], data[1::2])]
    return {'iocmatch': result}

"""
HashDump
"""
def collect_image_hash(dump_path):
    data = []
    try:
        output = subprocess.check_output(['vol', '-f', dump_path, 'windows.hashdump'])
    except subprocess.CalledProcessError as err:
        print('Error processing memory dump: ',err)
        return {'hashdump':[['Nothing was found.']]}
    hashdump_info = output.splitlines()
    for elem in hashdump_info[4:]:
        data.append(list(filter(None,elem.decode("utf-8").split('\t'))))
    return {'hashdump':data}

"""
FileScan
"""
def collect_image_files(dump_path):
    data = []
    try:
        output = subprocess.check_output(['vol', '-f', dump_path, 'windows.filescan'])
    except subprocess.CalledProcessError as err:
        print('Error processing memory dump: ',err)
        return {'filescan':[['Corrupted Dump']]}
    filescan_info = output.splitlines()
    for elem in filescan_info[4:]:
        data.append(list(filter(None,elem.decode("utf-8").split('\t'))))
    return {'filescan':data}
"""
Pstree
"""
def collect_image_pstree(dump_path):
    data = []
    try:
        output = subprocess.check_output(['vol', '-f', dump_path, 'windows.pstree'])
    except subprocess.CalledProcessError as err:
        print("Error processing memory dump: ", err)
        return {'pstree':[['Corrupted Dump']]}
    pstree_info = output.splitlines()
    for elem in pstree_info[4:]:
         data.append(list(filter(None,elem.decode("utf-8").split('\t'))))
    return {'pstree': data}

"""
Netscan
"""
def collect_image_netscan(dump_path):
    data = []
    try:
        output = subprocess.check_output(['vol', '-f', dump_path, 'windows.netscan'])
    except subprocess.CalledProcessError as err:
        print("Error processing memory dump: ", err)
        return {'netscan':[['Corrupted Dump']]}
    netscan_info = output.splitlines()
    for elem in netscan_info[4:]:
         data.append(list(filter(None,elem.decode("utf-8").split('\t'))))
    return {'netscan': data}

"""
PsScan
"""
def collect_image_psscan(dump_path):
    data = []
    try:
        output = subprocess.check_output(['vol', '-f', dump_path, 'windows.psscan'])
    except subprocess.CalledProcessError as err:
        print("Error processing memory dump: ", err)
        return {'psscan':[['Corrupted Dump']]}
    psscan_info = output.splitlines()
    for elem in psscan_info[4:]:
         data.append(list(filter(None,elem.decode("utf-8").split('\t'))))
    return {'psscan': data}

"""
Process graph
"""
def add_node(p,node,level):
    if level == 0:
        pid = str(p[0]).translate(str.maketrans('','','*'))
        node.append({'name': p[2], 'pid':pid, 'children':[]})
    else:
        add_node(p,node[len(node)-1]['children'],level-1)

def build_graph(pstree):
    data = []
    try:
        for p in pstree:
            level = str(p[0]).count('*')
            add_node(p,data,level)
        return {'graph': dumps(data)}
    except:
        return {'graph': dumps(data)}
"""
Process CmdLine
"""
def collect_image_cmdline(dump_path):
    data = []
    try:
        output = subprocess.check_output(['vol', '-f', dump_path, 'windows.cmdline'])
    except subprocess.CalledProcessError as err:
        print("Error processing memory dump: ", err)
        return {'cmdline':[['Corrupted Dump']]}
    cmdline_info = output.splitlines()
    for elem in cmdline_info:
         data.append(list(filter(None,elem.decode("utf-8").split('\t'))))
    return {'cmdline': data[4:]}

"""
Process Priviledges
"""

def collect_image_privileges(dump_path):
    data = []
    try:
        output = subprocess.check_output(['vol', '-f', dump_path, 'windows.privileges'])
    except subprocess.CalledProcessError as err:
        print("Error processing memory dump: ", err)
        return {'privileges':[['Corrupted Dump']]}
    privileges_info = output.splitlines()
    for elem in privileges_info:
         data.append(list(filter(None,elem.decode("utf-8").split('\t'))))
    return {'privileges': data[4:]}

"""
Malfind
"""

def malfind(dump_path):
    data = []
    try:
        output = subprocess.check_output(['vol', '-f', dump_path, 'windows.malfind'])
    except subprocess.CalledProcessError as err:
        print("Error processing memory dump: ", err)
        return {'malfind':[['Corrupted Dump']]}
    malware_info = output.splitlines()
    for elem in malware_info:
         data.append(list(filter(None,elem.decode("utf-8").split('\t'))))
    print(data)
    return {'malfind': data[4:]}

"""
Env
"""
def collect_image_env(dump_path):
    data = []
    try:
        output = subprocess.check_output(['vol', '-f', dump_path, 'windows.envars'])
    except subprocess.CalledProcessError as err:
        print("Error processing memory dump: ", err)
        return {'envars':[['Corrupted Dump']]}
    envars_info = output.splitlines()
    for elem in envars_info:
         data.append(list(filter(None,elem.decode("utf-8").split('\t'))))
    return {'envars': data[4:]}

"""
Process dump
"""
def dump_memory_pid(case_id,pid):
    case = UploadInvestigation.objects.get(pk=case_id)
    dump_path = case.file
    data = []
    try:
        output = subprocess.check_output(['vol', '-f', str(dump_path), '-o', 'Cases/Results/', 'windows.pslist', '--pid', pid, '--dump'])
        file_info = output.splitlines()
        for elem in file_info:
            data.append(list(filter(None,elem.decode("utf-8").split('\t'))))
        file_name = data[4][10]
        return file_name
    except:
        print("Error processing memory dump ")
        return "ERROR"

def build_timeline(data):
    timeline = []
    nb_event = 1
    actual_date = ""
    saved_date = str(data[0][2])
    for i in data:
        try:
            actual_date = str(i[2])
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
         output = subprocess.check_output(['vol', '-f', dump_path, 'timeliner.Timeliner'])
     except subprocess.CalledProcessError as err:
         print("Error processing memory dump: ", err)
         return {'timeline': ['no data']}
     timeline_info = output.splitlines()
     for elem in timeline_info:
          data.append(list(filter(None,elem.decode("utf-8").split('\t'))))
     return {'timeline': data[4:]}

"""
Main function : Launch each volatility modules dans save the result into the context variable.
"""
def launch_investigation(dump_path,id):
    #Check if the user did not cancel the analysis
    case = UploadInvestigation.objects.get(pk=id)
    if case.status == "0":
        print("Operation canceled")
        exit(1)

    #Collect IOCs with the strings utility
    iocs = NewIOC.objects.all()
    terms = ""
    ioc_result_name = "Cases/IOCs/iocs_invest_" + str(id)
    os.system("echo '' > "+ioc_result_name)
    for ioc in iocs:
        if str(id) in ioc.linkedInvestigationID or '-1' in ioc.linkedInvestigationID:
            terms = terms + ioc.value + "|"
    if terms != "":
        command = "strings -t d " + dump_path + ' | grep -E "' + terms[:len(terms)-1] + '" > ' + ioc_result_name
        os.system(command)
    #Check if the user did not cancel the analysis
    case = UploadInvestigation.objects.get(pk=id)
    if case.status == "0":
        print("Operation canceled")
        exit(1)

    #Run the iocs process extraction
    f_len = os.path.getsize(ioc_result_name)
    print('file_length ->', f_len)
    if f_len <= 1:
        iocmatch = {'iocmatch':[['No IOCs']]}
    else:
        iocmatch = collect_user_iocs(dump_path,ioc_result_name)

    #Check if the user did not cancel the analysis
    case = UploadInvestigation.objects.get(pk=id)
    if case.status == "0":
        print("Operation canceled")
        exit(1)

    #Extract hash
    hashdump = collect_image_hash(dump_path)

    #Check if the user did not cancel the analysis
    case = UploadInvestigation.objects.get(pk=id)
    if case.status == "0":
        print("Operation canceled")
        exit(1)

    #Extract files
    filescan = collect_image_files(dump_path)

    #Check if the user did not cancel the analysis (Nasty shit here Celery will solve that)
    case = UploadInvestigation.objects.get(pk=id)
    if case.status == "0":
        print("Operation canceled")
        exit(1)
    timeline = collect_image_timeline(dump_path)
    case = UploadInvestigation.objects.get(pk=id)
    if case.status == "0":
        print("Operation canceled")
        exit(1)
    timeline_chart = build_timeline(timeline['timeline'])
    case = UploadInvestigation.objects.get(pk=id)
    if case.status == "0":
        print("Operation canceled")
        exit(1)
    pstree = collect_image_pstree(dump_path)
    case = UploadInvestigation.objects.get(pk=id)
    if case.status == "0":
        print("Operation canceled")
        exit(1)
    graph = build_graph(pstree['pstree'])
    case = UploadInvestigation.objects.get(pk=id)
    if case.status == "0":
        print("Operation canceled")
        exit(1)
    netscan = collect_image_netscan(dump_path)
    case = UploadInvestigation.objects.get(pk=id)
    if case.status == "0":
        print("Operation canceled")
        exit(1)
    psscan = collect_image_psscan(dump_path)
    case = UploadInvestigation.objects.get(pk=id)
    if case.status == "0":
        print("Operation canceled")
        exit(1)
    cmdline = collect_image_cmdline(dump_path)
    case = UploadInvestigation.objects.get(pk=id)
    if case.status == "0":
        print("Operation canceled")
        exit(1)
    privileges = collect_image_privileges(dump_path)
    if case.status == "0":
        print("Operation canceled")
        exit(1)
    env = collect_image_env(dump_path)
    if case.status == "0":
        print("Operation canceled")
        exit(1)

    case.status = "2"
    case.save()
    global context
    context.update(pstree)
    context.update(psscan)
    context.update(netscan)
    context.update(graph)
    context.update(cmdline)
    context.update(privileges)
    context.update(env)
    context.update(timeline)
    context.update(timeline_chart)
    context.update(filescan)
    context.update(hashdump)
    context.update(iocmatch)
    with open('Cases/Results/'+str(id)+'.json', 'w') as json_file:
        json.dump(context, json_file)
