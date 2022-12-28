from django.shortcuts import render
from VolWeb.voltools import file_sha256, vt_check_file_hash
from .models import *
from django.core.serializers import json
from django.contrib.auth.decorators import login_required
from windows_engine.tasks import dump_memory_pid, app, dump_memory_file, compute_handles
from django.apps import apps
from django.http import JsonResponse, HttpResponse
from .forms import *
import os, uuid, mimetypes
from zipfile import ZipFile
from .report import report



@login_required
def get_handles(request):
    """Get handles from a PID

    Arguments:
    request : http request object

    Comment:
    The user requested to watch the handles linked to a process. 
    If the handles are already calculated, then the result is fetch
    Else, volatility3 will calculate them using celery.
    """
    if request.method == 'GET':

        form = GetArtifacts(request.GET)
        if form.is_valid():
            case = form.cleaned_data['case']
            id = case.id
            pid = form.cleaned_data['pid']
            json_serializer = json.Serializer()
            # Check if the Handles are not already computed
            handles = Handles.objects.filter(investigation_id=id, PID=pid)
            if len(handles)>0: 
                #Already computed we display the result
                artifacts = {
                    'Handles': json_serializer.serialize(handles),
                }
            else:
                #start a task with celery to compute the handles and send the result.
                task_res = compute_handles.delay(str(id), str(pid))
                res =  task_res.get()
                if res != "OK":
                    return JsonResponse({'message': "error"})
                else:
                    artifacts = {
                        'Handles': json_serializer.serialize(Handles.objects.filter(investigation_id=id, PID=pid)),
                    }
            return JsonResponse({'message': "success", 'artifacts': artifacts})
    
    return JsonResponse({'message': "error"})



@login_required
def get_interval(request):
    """Get artifacts for a specific timestamp

    Arguments:
    request : http request object

    Comment:
    The user requested to watch the artifacts linked to a specific timestamp.
    """
    if request.method == 'GET':
        form = GetInverval(request.GET)
        if form.is_valid():
            case = form.cleaned_data['case']
            date = form.cleaned_data['date']
            id = case.id
            json_serializer = json.Serializer()
            # Request the appropriate artifacts
            artifacts = {
                'Timeliner': json_serializer.serialize(Timeliner.objects.filter(investigation_id=id,CreatedDate=date)),
            }
            return JsonResponse({'message': "success", 'artifacts': artifacts})
    
    return JsonResponse({'message': "error"})


@login_required
def get_w_artifacts(request):
    """Get artifacts related to all process related volatility3 plugins

    Arguments:
    request : http request object

    Comment:
    The user requested to watch the artifacts linked the process.
    """
    if request.method == 'GET':
        form = GetArtifacts(request.GET)
        if form.is_valid():
            case = form.cleaned_data['case']
            pid = form.cleaned_data['pid']
            id = case.id
            json_serializer = json.Serializer()
            # Request the appropriate artifacts
            artifacts = {
                'CmdLine': json_serializer.serialize(CmdLine.objects.filter(investigation_id=id, PID=pid)),
                'DllList': json_serializer.serialize(DllList.objects.filter(investigation_id=id, PID=pid)),
                'Privs':   json_serializer.serialize(Privs.objects.filter(investigation_id=id, PID=pid)),
                'Envars':  json_serializer.serialize(Envars.objects.filter(investigation_id=id, PID=pid)),
                'NetScan': json_serializer.serialize(NetScan.objects.filter(investigation_id=id, PID=pid)),
                'NetStat': json_serializer.serialize(NetStat.objects.filter(investigation_id=id, PID=pid)),
                'Sessions': json_serializer.serialize(Sessions.objects.filter(investigation_id=id, ProcessID=pid)),
                'LdrModules': json_serializer.serialize(LdrModules.objects.filter(investigation_id=id, Pid=pid)),
            }
            return JsonResponse({'message': "success", 'artifacts': artifacts})
    return JsonResponse({'message': "error"})

@login_required
def win_report(request):
    """
    Generate the windows report
    """
    form = ReportForm(request.POST)
    if form.is_valid():
        case = form.cleaned_data['case_id']
        html, text = report(case)
        return JsonResponse({'message': "success", 'html': html, 'text': text})
    else:
        return JsonResponse({'message': "error"})


@login_required
def win_tag(request):
    """
    Tag a Windows artifact
    """
    if request.method == 'POST':
        form = Tag(request.POST)
        if form.is_valid():
            item = apps.get_model("windows_engine", form.cleaned_data['plugin_name']).objects.get(
                id=form.cleaned_data['artifact_id'])

            if form.cleaned_data['status'] == "Evidence":
                item.Tag = "Evidence"
            elif form.cleaned_data['status'] == "Suspicious":
                item.Tag = "Suspicious"
            else:
                item.Tag = None
            item.save()
            return JsonResponse({'message': "success"})
        else:
            return JsonResponse({'message': "error"})


@login_required
def dump_process(request):
    """Dump a process

        Arguments:
        request : http request object

        Comment:
        Get the process PID passed by the user.
        Dump the process via volatility delegated to celery.
        Send the proper response (failed, success, error).
        """
    if request.method == 'POST':
        form = DumpMemory(request.POST)
        if form.is_valid():
            case_id = form.cleaned_data['case_id']
            pid = form.cleaned_data['pid']
            if len(ProcessDump.objects.filter(pid=pid, case_id=case_id)) > 0:
                file_path = ProcessDump.objects.get(case_id=case_id, pid=pid)
                return JsonResponse({'message': "exist", 'id': file_path.process_dump_id})
            task_res = dump_memory_pid.delay(str(case_id.id), str(pid))
            file_path = task_res.get()
            if file_path != "ERROR":
                # create ProcessDump model :
                Dump = form.save()
                Dump.filename = file_path
                Dump.save()
                dump_id = Dump.process_dump_id
                return JsonResponse({'message': "success", 'id': dump_id})
            else:
                return JsonResponse({'message': "failed"})
        else:
            return JsonResponse({'message': "error"})
    return JsonResponse({'message': "error"})


@login_required
def dump_file(request):
    """Dump a file

        Arguments:
        request : http request object

        Comment:
        Get the file offset passed by the user.
        Dump the file via volatility delegated to celery.
        Send the proper response (failed, success, error).
        """
    if request.method == 'POST':
        form = DumpFile(request.POST)
        if form.is_valid():
            case_id = form.cleaned_data['case_id']
            offset = form.cleaned_data['offset']
            if len(FileDump.objects.filter(offset=offset, case_id=case_id)) > 0:
                file = FileDump.objects.get(case_id=case_id, offset=offset)
                return JsonResponse({'message': "exist", 'id': file.file_dump_id})
            task_res = dump_memory_file.delay(str(case_id.id), offset)
            files = task_res.get()
            if files == "ERROR":
                return JsonResponse({'message': "failed"})

            to_zip = []
            for file in files:
                if file['Result'] != "Error dumping file":
                    to_zip.append(file['Result'])
            if to_zip:
                # Creating our zip file
                zip_file_name = str(uuid.uuid4()) + ".zip"
                path = 'Cases/Results/file_dump_' + str(case_id.id) + "/"
                with ZipFile(path + zip_file_name, 'w') as zip:
                    for file in to_zip:
                        zip.write(path + file)
                # create ProcessDump model :
                Dump = form.save()
                Dump.filename = zip_file_name
                Dump.save()
                file_id = Dump.file_dump_id
                return JsonResponse({'message': "success", 'id': file_id})
            else:
                return JsonResponse({'message': "failed"})
        else:
            return JsonResponse({'message': "error"})


@login_required
def vt_hash_check(request):
    """
    Check file score on virus total
    """
    if request.method == 'POST':
        form = DumpFile(request.POST)

        if form.is_valid():
            case_id = form.cleaned_data['case_id']
            offset = form.cleaned_data['offset']
            task_res = dump_memory_file.delay(str(case_id.id), offset)
            files = task_res.get()
            if files == "ERROR":
                return JsonResponse({'message': "failed_2"})
            path = 'Cases/Results/file_dump_' + str(case_id.id) + "/"
            for file in files:
                if file['Result'] != "Error dumping file":
                    sha256 = file_sha256(path + file['Result'])
                    result, message = vt_check_file_hash(sha256)
                    if not result:
                        continue
                    else:
                        result.update({'message': "success"})
                        return JsonResponse(result)
                else:
                    return JsonResponse({'message': "failed_2"})
            return JsonResponse({'message': "failed_1", 'error': message})

        else:
            return JsonResponse({'message': "error"})


@login_required
def download_hive(request):
    """Download a dumped hive

        Arguments:
        request : http request object

        Comment:
        The user requested to download a dumped hive.
        Get the hive and return it.
        """
    if request.method == 'POST':
        form = DownloadHive(request.POST)
        if form.is_valid():
            file_path = form.cleaned_data['filename']
            ext = os.path.basename(file_path).split('.')[-1].lower()
            if ext in ['hive']:
                filename = file_path
                file_path = "Cases/files/" + file_path
                path = open(file_path, 'rb')
                mime_type, _ = mimetypes.guess_type(file_path)
                response = HttpResponse(path, content_type=mime_type)
                response['Content-Disposition'] = "attachment; filename=%s" % filename
                return response


@login_required
def download_dump(request):
    """Download a dumped process

        Arguments:
        request : http request object

        Comment:
        The user requested to download a successfull dumped process.
        Get the file and return it.
        """
    if request.method == 'POST':
        form = DownloadDump(request.POST)
        if form.is_valid():
            dump_id = form.cleaned_data['id']
            Dump = ProcessDump.objects.get(process_dump_id=dump_id)
            file_path = Dump.filename
            case_path = 'Cases/Results/process_dump_' + str(Dump.case_id.id)
            ext = os.path.basename(file_path).split('.')[-1].lower()
            if ext in ['dmp']:
                filename = file_path
                file_path = case_path + "/" + file_path
                path = open(file_path, 'rb')
                mime_type, _ = mimetypes.guess_type(file_path)
                response = HttpResponse(path, content_type=mime_type)
                response['Content-Disposition'] = "attachment; filename=%s" % filename
                return response


@login_required
def download_file(request):
    """Download a dumped file

        Arguments:
        request : http request object

        Comment:
        The user requested to download a successfull dumped file.
        Get the file and return it.
        """
    if request.method == 'POST':
        form = DownloadFile(request.POST)
        if form.is_valid():
            file_id = form.cleaned_data['id']
            Dump = FileDump.objects.get(file_dump_id=file_id)
            file_path = Dump.filename
            case_path = 'Cases/Results/file_dump_' + str(Dump.case_id.id)
            ext = os.path.basename(file_path).split('.')[-1].lower()
            if ext in ['zip']:
                filename = file_path
                file_path = case_path + "/" + file_path
                path = open(file_path, 'rb')
                mime_type, _ = mimetypes.guess_type(file_path)
                response = HttpResponse(path, content_type=mime_type)
                response['Content-Disposition'] = "attachment; filename=%s" % filename
                return response
