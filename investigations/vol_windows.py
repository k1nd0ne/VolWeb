from json import dumps
import subprocess, time, json, re, os
"""
Process IOC Extraction
"""
def collect_user_iocs(dump_path,investigation_ioc_path):
    data = []
    try:
        output = subprocess.check_output(['vol', '-r', 'json', '-f', dump_path, 'windows.strings' ,'--strings-file', investigation_ioc_path])
    except subprocess.CalledProcessError as err:
        print("Error processing memory dump: ", err)
        return {'iocmatch':[['Nothing Found']]}
    strings_info = output.decode()
    data = json.loads(strings_info)
    return {'iocmatch': data}

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
        output = subprocess.check_output(['vol', '-r', 'json', '-f', dump_path, 'windows.filescan'])
    except subprocess.CalledProcessError as err:
        print('Error processing memory dump: ',err)
        return {'filescan':[['Corrupted Dump']]}
    imagef_info = output.decode()
    data = json.loads(imagef_info)
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
        output = subprocess.check_output(['vol', '-r', 'json', '-f', dump_path, 'windows.netscan'])
    except subprocess.CalledProcessError as err:
        print("Error processing memory dump: ", err)
        return {'netscan':[['Corrupted Dump']]}
    netscan_info = output.decode()
    data = json.loads(netscan_info)
    return {'netscan': data}


"""
Netstat
"""
def collect_image_netstat(dump_path):
    data = []
    try:
        output = subprocess.check_output(['vol', '-r', 'json', '-f', dump_path, 'windows.netstat'])
    except subprocess.CalledProcessError as err:
        print("Error processing memory dump: ", err)
        return {'netstat':[['Corrupted Dump']]}
    netstat_info = output.decode()
    data = json.loads(netstat_info)
    return {'netstat': data}

"""
Network Graph
"""
def generate_network_graph(data):
    graph_data = {'nodes':[], 'edges':[]}
    for entrie in data:
        node_data_1 = {'id':entrie['LocalAddr'], 'Involved_PIDs': [entrie['PID']], 'Owner(s)': [entrie['Owner']], 'Local_Ports':[entrie['LocalPort']], 'State':entrie['State']}
        node_data_2 = {'id':entrie['ForeignAddr'], 'Involved_PIDs': [entrie['PID']], 'Owner(s)': [entrie['Owner']], 'Local_Ports':[entrie['ForeignPort']], 'State':entrie['State']}
        edge_data = {'from': entrie['LocalAddr'], 'to': entrie['ForeignAddr']}


        if not graph_data['nodes']:
            graph_data['nodes'].append(node_data_1)

        is_present = False
        for item in graph_data['nodes']:
            if node_data_1['id'] == item['id']:
                is_present = True
                break
        if not is_present:
            graph_data['nodes'].append(node_data_1)
        else:
            if entrie['PID'] not in item['Involved_PIDs']:
                item['Involved_PIDs'].append(entrie['PID'])
            if entrie['LocalPort'] not in item['Local_Ports']:
                item['Local_Ports'].append(entrie['LocalPort'])
            if entrie['Owner'] not in item['Owner(s)']:
                item['Owner(s)'].append(entrie['Owner'])

        is_present = False
        for item in graph_data['nodes']:
            if node_data_2['id'] == item['id']:
                is_present = True
                break

        if not is_present:
            graph_data['nodes'].append(node_data_2)
        else:
            if entrie['PID'] not in item['Involved_PIDs']:
                item['Involved_PIDs'].append(entrie['PID'])
            if entrie['ForeignPort'] not in item['Local_Ports']:
                item['Local_Ports'].append(entrie['ForeignPort'])
            if entrie['Owner'] not in item['Owner(s)']:
                item['Owner(s)'].append(entrie['Owner'])

        if edge_data not in graph_data['edges']:
            graph_data['edges'].append(edge_data)

    return {'network_graph' : json.dumps(graph_data)}


"""
PsScan
"""
def collect_image_psscan(dump_path):
    data = []
    try:
        output = subprocess.check_output(['vol', '-r', 'json', '-f', dump_path, 'windows.psscan'])
    except subprocess.CalledProcessError as err:
        print("Error processing memory dump: ", err)
        return {'psscan':[['Corrupted Dump']]}
    psscan_info = output.decode()
    data = json.loads(psscan_info)
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
        output = subprocess.check_output(['vol', '-r', 'json', '-f', dump_path, 'windows.cmdline'])
    except subprocess.CalledProcessError as err:
        print("Error processing memory dump: ", err)
        return {'cmdline':[['Corrupted Dump']]}
    cmdline_info = output.decode()
    data = json.loads(cmdline_info)
    return {'cmdline': data}

"""
Process Priviledges
"""
def collect_image_privileges(dump_path):
    data = []
    try:
        output = subprocess.check_output(['vol', '-r', 'json', '-f', dump_path, 'windows.privileges'])
    except subprocess.CalledProcessError as err:
        print("Error processing memory dump: ", err)
        return {'privileges':[['Corrupted Dump']]}
    privileges_info = output.decode()
    data = json.loads(privileges_info)
    return {'privileges': data}

"""
Malfind
"""
def malfind(dump_path):
    data = []
    try:
        output = subprocess.check_output(['vol', '-r', 'json', '-f', dump_path, 'windows.malfind'])
    except subprocess.CalledProcessError as err:
        print("Error processing memory dump: ", err)
        return {'malfind':[['Corrupted Dump']]}
    malware_info = output.decode()
    data = json.loads(malware_info)
    return {'malfind': data}

"""
Lsa Dump
"""
def lsa_dump(dump_path):
    data = []
    try:
        output = subprocess.check_output(['vol', '-r', 'json', '-f', dump_path, 'windows.lsadump'])
    except subprocess.CalledProcessError as err:
        print("Error processing memory dump: ", err)
        return {'lsadump':[['Corrupted Dump']]}
    lsadump = output.decode()
    data = json.loads(lsadump)
    return {'lsadump': data}

"""
Cache Dump
"""
def cache_dump(dump_path):
    data = []
    try:
        output = subprocess.check_output(['vol', '-r', 'json', '-f', dump_path, 'windows.cachedump'])
    except subprocess.CalledProcessError as err:
        print("Error processing memory dump: ", err)
        return {'cachedump':[['Corrupted Dump']]}
    cachedump = output.decode()
    data = json.loads(cachedump)
    return {'cachedump': data}

"""
Skeleton Key Check
"""
def skc(dump_path):
    data = []
    try:
        output = subprocess.check_output(['vol', '-r', 'json', '-f', dump_path, 'windows.skeleton_key_check'])
    except subprocess.CalledProcessError as err:
        print("Error processing memory dump: ", err)
        return {'skeleton_key_check':[['Corrupted Dump']]}
    skeleton = output.decode()
    data = json.loads(skeleton)
    return {'skeleton': data}

"""
Env
"""
def collect_image_env(dump_path):
    data = []
    try:
        output = subprocess.check_output(['vol', '-r', 'json', '-f', dump_path, 'windows.envars'])
    except subprocess.CalledProcessError as err:
        print("Error processing memory dump: ", err)
        return {'envars':[['Corrupted Dump']]}
    envars_info = output.decode()
    data = json.loads(envars_info)
    return {'envars': data}
