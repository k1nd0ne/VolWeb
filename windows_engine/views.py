from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from windows_engine.tasks import dump_memory_pid, app, dump_memory_file
from django.apps import apps
from django.http import JsonResponse, HttpResponse
from .forms import *
import os, uuid, subprocess, mimetypes
from zipfile import ZipFile
from .report import report
@login_required
def win_report(request):
    form = ReportForm(request.POST)
    if form.is_valid():
            case = form.cleaned_data['case_id']
            html, text = report(case)
            return JsonResponse({'message': "success",'html':html, 'text':text})
    else:
        return JsonResponse({'message': "error"})



@login_required
def tag(request):
    """Tag a Windows artifact
    """
    if request.method == 'POST':
        form = Tag(request.POST)
        if form.is_valid():
            item = apps.get_model("windows_engine", form.cleaned_data['plugin_name']).objects.get(id=form.cleaned_data['artifact_id'])

            if form.cleaned_data['status'] == "Evidence":
                item.Tag = "Evidence"
            elif form.cleaned_data['status'] == "Suspicious":
                item.Tag = "Suspicious"
            else:
                item.Tag = None
            print(item.Tag)
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
            if len(ProcessDump.objects.filter(pid = pid, case_id = case_id)) > 0:
                file_path = ProcessDump.objects.get(case_id=case_id, pid=pid)
                return JsonResponse({'message': "exist", 'id': file_path.process_dump_id})
            task_res = dump_memory_pid.delay(str(case_id.id),str(pid))
            file_path = task_res.get()
            if file_path != "ERROR":
                #create ProcessDump model :
                Dump = form.save()
                Dump.filename = file_path
                Dump.save()
                dump_id = Dump.process_dump_id
                return JsonResponse({'message': "success",'id': dump_id })
            else:
                return JsonResponse({'message': "failed"})
        else:
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
            if len(FileDump.objects.filter(offset = offset, case_id = case_id)) > 0:
                file = FileDump.objects.get(case_id=case_id, offset=offset)
                return JsonResponse({'message': "exist", 'id': file.file_dump_id})
            task_res = dump_memory_file.delay(str(case_id.id),offset)
            files = task_res.get()
            if files == "ERROR":
                return JsonResponse({'message': "failed"})

            to_zip = []
            for file in files:
                if file['Result'] != "Error dumping file":
                    to_zip.append(file['Result'])
            if to_zip:
                #Creating our zip file
                zip_file_name = str(uuid.uuid4())+".zip"
                path = 'Cases/Results/file_dump_'+str(case_id.id)+"/"
                with ZipFile(path+zip_file_name,'w') as zip:
                    for file in to_zip:
                        zip.write(path+file)
                #create ProcessDump model :
                Dump = form.save()
                Dump.filename = zip_file_name
                Dump.save()
                file_id = Dump.file_dump_id
                return JsonResponse({'message': "success",'id': file_id})
            else:
                return JsonResponse({'message': "failed"})
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
                file_path = "Cases/files/"+file_path
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
            Dump = ProcessDump.objects.get(process_dump_id = dump_id)
            file_path = Dump.filename
            case_path = 'Cases/Results/process_dump_'+str(Dump.case_id.id)
            ext = os.path.basename(file_path).split('.')[-1].lower()
            if ext in ['dmp']:
                filename = file_path
                file_path = case_path+"/"+file_path
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
            Dump = FileDump.objects.get(file_dump_id = file_id)
            file_path = Dump.filename
            print(file_path)
            case_path = 'Cases/Results/file_dump_'+str(Dump.case_id.id)
            ext = os.path.basename(file_path).split('.')[-1].lower()
            if ext in ['zip']:
                filename = file_path
                file_path = case_path+"/"+file_path
                path = open(file_path, 'rb')
                mime_type, _ = mimetypes.guess_type(file_path)
                response = HttpResponse(path, content_type=mime_type)
                response['Content-Disposition'] = "attachment; filename=%s" % filename
                return response
