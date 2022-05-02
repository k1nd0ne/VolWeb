#############################################################################################################################
#This part is temporary for the 1.0.0-alpha and will use the volatility3 library for the 2.0.0-alpha                        #
#############################################################################################################################
from .models import *
from iocs.models import IOC
from .celery import app
from json import dumps
import hashlib
import subprocess, time, json, re, os
from .vol_windows import *
from .vol_linux import *

WINDOWS_MODULES_TO_RUN = 18
LINUX_MODULES_TO_RUN = 0
MAC_MODULES_TO_RUN = 0
PARTIAL_RESULTS = False
"""Progress"""
def update_progress(case):
    global WINDOWS_MODULES_TO_RUN
    percentage = str(format(float(case.percentage) + float(100/WINDOWS_MODULES_TO_RUN), '.2f'))
    print(percentage)
    case.percentage = percentage
    case.save()

"""Calculate memory image dump"""
def memory_image_hash(dump_path):
    BLOCKSIZE = 65536            # lets read stuff in 64kb chunks!
    hasher = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    try:
        with open(dump_path, 'rb') as afile:
            buf = afile.read(BLOCKSIZE)

            while len(buf) > 0:
                hasher.update(buf)
                sha1.update(buf)
                sha256.update(buf)
                buf = afile.read(BLOCKSIZE)
        sha256_hash = {'hash' : {'md5':format(hasher.hexdigest()), 'sha1': format(sha1.hexdigest()), 'sha256': format(sha256.hexdigest())}}
    except:
        sha256_hash = {'hash' : {'md5':'Error', 'sha1': 'Error', 'sha256': 'Error'}}
    return sha256_hash

"""Process dump task"""
@app.task(name="dump_memory_pid")
def dump_memory_pid(case_id,pid):
    
    case = UploadInvestigation.objects.get(pk=case_id)
    dump_path = "Cases/" + case.name
    output_path = 'Cases/Results/process_dump_'+case_id
    data = []
    try:
        subprocess.check_output(['mkdir', output_path])
    except:
        pass
    try:
        output = subprocess.check_output(['vol', '-r', 'json', '-f', str(dump_path), '-o', output_path, 'windows.pslist', '--pid', pid, '--dump'],timeout=120)
        dump_info = output.decode()
        raw_data = json.loads(dump_info)
        data = {k.replace(" ", "_"): v for k, v in raw_data[0].items()}
        return data['File_output']
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
    try:
        output = subprocess.check_output(['vol', '-r', 'json', '-f', str(dump_path), '-o', output_path, 'windows.dumpfiles', '--physaddr', hex(offset)],timeout=120)
        filedump_info = output.decode()
        data = json.loads(filedump_info)
        print(data)
        return data[0]['Result']
    except:
        try:
            output = subprocess.check_output(['vol', '-r', 'json', '-f', str(dump_path), '-o', output_path, 'windows.dumpfiles', '--virtaddr', hex(offset)],timeout=120)
            filedump_info = output.decode()
            data = json.loads(filedump_info)
            return data[0]['Result']
        except subprocess.CalledProcessError as err:
            print('Error processing memory dump: ',err)
            return "ERROR"
        except:
            print('The specific file could not be dumped.')
            return "ERROR"


"""Build Timeline"""
def build_timeline(data):
    timeline = []
    nb_event = 1
    actual_date = ""
    try:
        saved_date = data[0]["Created Date"]
    except:
        raise VolatilityError
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
            raise GraphError('could not generate timeline graph')
    return {"linechart": dumps(timeline)}

"""Dump Timeline"""
def collect_image_timeline(dump_path):
     data = []
     try:
         output = subprocess.check_output(['vol', '-r','json', '-f', dump_path, 'timeliner.Timeliner'],timeout=250)
     except subprocess.CalledProcessError as err:
         raise VolatilityError(f"Error processing memory dump: {err}")
     except subprocess.TimeoutExpired as err:
         raise VolatilityError(f"Module timeout: {err}")
     timeline_info = output.decode()
     data = json.loads(timeline_info)
     return {'timeline': data}


"""Windows automatic analysis"""
def windows_memory_analysis(dump_path,case):
    global PARTIAL_RESULTS
    #Collect IOCs with the strings utility
    iocs = IOC.objects.all()
    terms = ""
    ioc_result_name = "Cases/IOCs/iocs_invest_" + str(case.id)
    strings_output_file = "Cases/IOCs/output_"+ str(case.id)

    with open(ioc_result_name, 'w') as fout:
        fout.write('')
        fout.close()

    for ioc in iocs:
        if (str(case.id) == str(ioc.linkedInvestigation)):
            terms = terms + ioc.value + "|"
    if terms != "":
        with open(strings_output_file, 'w') as fout:
            try:
                fout.write(subprocess.check_output(['strings', '-t', 'd', dump_path]).decode())
            except subprocess.CalledProcessError as e:
                print("Could not execute the strings command : ", e.output)
            fout.close()
        with open(ioc_result_name, 'w') as fout:
            try:
                fout.write(subprocess.check_output(['grep', '-E', terms[:len(terms)-1] ,  strings_output_file]).decode())
            except subprocess.CalledProcessError as e:
                print("No IOCs found : ",e.output)
            fout.close()
    f_len = os.path.getsize(ioc_result_name)
    if f_len <= 1:
        iocmatch = {'iocmatch':[['No String based IOCs']]}
    else:
        iocmatch = collect_user_iocs(dump_path,ioc_result_name)

    #Calculate dump sha256
    sha256_hash = memory_image_hash(dump_path)
    # Run volatility modules and get the results this solution is temporary until I learn how to use the volatility3 framework as a library.
    try:
        malwarefind = malfind(dump_path)
    except VolatilityError:
        malwarefind = {'malfind':[['Nothing was found.']]}
        PARTIAL_RESULTS = True
    update_progress(case)

    try:
        hashdump = collect_image_hash(dump_path)
    except VolatilityError:
        hashdump = {'hashdump':[['Nothing was found.']]}
        PARTIAL_RESULTS = True
    update_progress(case)

    try:
        filescan = collect_image_files(dump_path)
    except VolatilityError:
        filescan = {'filescan':[['Corrupted Dump']]}
        PARTIAL_RESULTS = True
    update_progress(case)

    try:
        timeline = collect_image_timeline(dump_path)
        timeline_chart = build_timeline(timeline['timeline'])
    except VolatilityError as err:
        print(f'error occured : {err}')
        timeline = {'timeline': ['no data']}
        timeline_chart = {"linechart": [['Not Available']]}
        PARTIAL_RESULTS = True
    except GraphError:
        timeline_chart = {"linechart": [['Not Available']]}
        PARTIAL_RESULTS = True
    update_progress(case)
    update_progress(case)

    try:
        pstree = collect_image_pstree(dump_path)
        graph = build_graph(pstree['pstree'])
    except VolatilityError:
        pstree = {'pstree':[['Corrupted Dump']]}
        graph = {'graph':[['Corrupted Dump']]}
        PARTIAL_RESULTS = True
    except GraphError:
        graph = {'graph':[['Corrupted Dump']]}
        PARTIAL_RESULTS = True
    update_progress(case)
    update_progress(case)

    try:
        netscan = collect_image_netscan(dump_path)
    except VolatilityError:
        netscan = {'netscan':[['Corrupted Dump']]}
        PARTIAL_RESULTS = True
    update_progress(case)

    try:
        netstat = collect_image_netstat(dump_path)
    except VolatilityError:
        netstat = {'netstat':[['Corrupted Dump']]}
        PARTIAL_RESULTS = True
    update_progress(case)
    try:
        netgraph = generate_network_graph(netscan['netscan'] + netstat['netstat'])
    except:
        netgraph = {'network_graph': [['no data']]}
        PARTIAL_RESULTS = True
    update_progress(case)

    try:
        psscan = collect_image_psscan(dump_path)
    except VolatilityError:
        psscan = {'psscan':[['Corrupted Dump']]}
        PARTIAL_RESULTS = True
    update_progress(case)

    try:
        cmdline = collect_image_cmdline(dump_path)
    except VolatilityError:
        cmdline = {'cmdline':[['Corrupted Dump']]}
        PARTIAL_RESULTS = True
    update_progress(case)

    try:
        privileges = collect_image_privileges(dump_path)
    except:
        privileges = {'privileges':[['Corrupted Dump']]}
        PARTIAL_RESULTS = True
    update_progress(case)

    try:
        env = collect_image_env(dump_path)
    except VolatilityError:
        env = {'envars':[['Corrupted Dump']]}
        PARTIAL_RESULTS = True
    update_progress(case)

    try:
        skeleton = skc(dump_path)
    except:
        skeleton = {'skeleton':[['Corrupted Dump']]}
        PARTIAL_RESULTS = True
    update_progress(case)

    try:
        lsadump = lsa_dump(dump_path)
    except VolatilityError:
        lsadump = {'lsadump':[['Corrupted Dump']]}
        PARTIAL_RESULTS = True
    update_progress(case)

    try:
        cachedump = cache_dump(dump_path)
    except VolatilityError:
        cachedump = {'cachedump':[['Corrupted Dump']]}
        PARTIAL_RESULTS = True
    update_progress(case)

    try:
        hivelist = collect_image_hivelist(dump_path)
    except:
        hivelist = {'hivescan':[['Corrupted Dump']]}
        PARTIAL_RESULTS = True
    update_progress(case)

    #Save the result to json
    results = { **sha256_hash, **malwarefind, **pstree, **psscan,
              **netscan, **netstat, **netgraph,
              **graph, **cmdline, **privileges,
              **env, **timeline, **timeline_chart,
              **filescan, **hashdump, **iocmatch, **skeleton,
              **lsadump, **cachedump, **hivelist }
    with open('Cases/Results/'+str(case.id)+'.json', 'w') as json_file:
        json.dump(results, json_file)
    if PARTIAL_RESULTS:
        case.status = "4"
    else:
        case.status = "2"

    case.percentage = "100"
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
    operating_system = os_detection(dump_path)
    if operating_system == -1:
        print("Error Getting The OS")
    elif operating_system > 0:
        print("OS Detected as Linux")
        linux_memory_analysis(dump_path,case)
    else:
        print("OS detected as Windows")
        windows_memory_analysis(dump_path,case)
