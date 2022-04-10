from json import dumps
import subprocess, time, json, re, os

"""
Pstree
"""
def collect_linux_image_pstree(dump_path):
    data = []
    try:
        output = subprocess.check_output(['vol', '-f', dump_path, 'linux.pstree'])
    except subprocess.CalledProcessError as err:
        print("Error processing memory dump: ", err)
        return {'pstree':[['Corrupted Dump']]}
    pstree_info = output.splitlines()
    for elem in pstree_info[4:]:
         data.append(list(filter(None,elem.decode("utf-8").split('\t'))))
    return {'pstree': data}
