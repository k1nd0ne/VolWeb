from .tasks import start_memory_analysis, dump_memory_pid, app, dump_memory_file
from django.http import HttpResponse, FileResponse, JsonResponse
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth import get_user_model
from django.shortcuts import render
from django.core.serializers import serialize
from celery.result import AsyncResult
from django.contrib import messages
import json, os, uuid, subprocess, mimetypes
from zipfile import ZipFile
from iocs.models import IOC
from os.path import exists
from investigations.models import *
import windows_engine.models as windows_engine
import linux_engine.models as linux_engine
from symbols.models import Symbols
from investigations.forms import *

@login_required
def investigations(request):
    """Investigation dashboard

    Arguments:
    request : http request object

    Comment:
    First entry point to visualise all of the investigations
    """
    form = ManageInvestigation()
    return render(request,'investigations/investigations.html',{'investigations': UploadInvestigation.objects.all(), 'form': form})

@login_required
def newinvest(request):
    """Create a new investigation

            Arguments:
            request : http request object

            Comment:
            Handle the file upload chunck by chunck.
            Create the investigation if the upload is successfull.
            """
    if request.method == 'POST':
        form = UploadFileForm(request.POST)
        if form.is_valid():
            title = form.cleaned_data['title']
            os_version = form.cleaned_data['os_version']
            investigators = form.cleaned_data['investigators']
            description = form.cleaned_data['description']
            file = request.FILES['file'].read()
            fileName= form.cleaned_data['name']
            existingPath = request.POST['existingPath']
            end = request.POST['eof']
            nextSlice = request.POST['nextSlice']
        else:
            return JsonResponse({'data': form.errors})
        if file=="" or fileName=="" or existingPath=="" or end=="" or nextSlice=="":
            return JsonResponse({'data':'Invalid Request'})
        else:
            if existingPath == 'null':
                uid = uuid.uuid4()
                fileName = str(uid) + "_" + fileName
                path = 'Cases/' + fileName
                with open(path, 'wb+') as destination:
                    destination.write(file)
                FileFolder = UploadInvestigation()
                FileFolder.title = title
                FileFolder.os_version = os_version
                FileFolder.investigators = investigators
                FileFolder.description = description
                FileFolder.status = "0"
                FileFolder.percentage = "0"
                FileFolder.existingPath = fileName
                FileFolder.eof = end
                FileFolder.name = fileName
                FileFolder.uid = uid
                FileFolder.save()
                if int(end):
                    res = JsonResponse({'data':'Uploaded Successfully','existingPath': fileName})
                else:
                    res = JsonResponse({'existingPath': fileName})
                return res
            else:
                path = 'Cases/' + existingPath
                model_id = UploadInvestigation.objects.get(existingPath=existingPath)
                if model_id.name == existingPath:
                    if not model_id.eof:
                        with open(path, 'ab+') as destination:
                            destination.write(file)
                            if int(end):
                                model_id.eof = int(end)
                                model_id.save()
                                model_id.update_activity()
                                res = JsonResponse({'data':'Uploaded Successfully','existingPath':model_id.existingPath})
                            else:
                                res = JsonResponse({'existingPath':model_id.existingPath})
                                return res
                    else:
                        res = JsonResponse({'data':'EOF found. Invalid request'})
                        return res
                else:
                    res = JsonResponse({'data':'No such file exists in the existingPath'})
                    return res
    form = UploadFileForm()
    User = get_user_model()
    return render(request, 'investigations/newinvest.html', {'form': form, 'Users':User.objects.filter(is_superuser = False)})


@login_required
def get_invest(request):
    """Get the investigation details

        Arguments:
        request : http request object

        Comment:
        When a user click on an investigation card, this function load the details about it.
        """
    if request.method == 'GET':
        form = ManageInvestigation(request.GET)
        if form.is_valid():
            id = form.cleaned_data['sa_case_id'].id
            try:
                u = UploadInvestigation.objects.get(pk=id)
                response = serialize('python', [u], ensure_ascii=False, fields=('title','name', 'investigators', 'description', 'status', 'percentage'))
            except ObjectDoesNotExist:
                response = {'message':'N/A'}
            try:
                i = IOC.objects.filter(linkedInvestigation=id)
                iocs = serialize('python', list(i), ensure_ascii=False, fields=('value','context'))
            except ObjectDoesNotExist:
                iocs = {'message':'N/A'}
            try:
                u = UploadInvestigation.objects.get(pk=id)
                s = u.linked_isf
                if s:
                    isf = serialize('json',[s, ], fields=('name','description'))
                else:
                    isf = {'message':'N/A'}

            except ObjectDoesNotExist:
                isf = {'message':'N/A'}
            return JsonResponse({'message': "success", 'result':response,'iocs':iocs,'isf':isf})
        else:
            return JsonResponse({'message': "error"})

@login_required
def start_analysis(request):
    """Start the analysis

        Arguments:
        request : http request object

        Comment:
        The user clicked on the "Start analysis" button.
        """
    if request.method == 'POST':
        form = ManageInvestigation(request.POST)
        if form.is_valid():
            case = form.cleaned_data['sa_case_id']
            case.status = "1"
            case.percentage = "0"
            result = start_memory_analysis.delay('Cases/'+str(case.name),case.id)
            case.taskid = result
            case.save()
            return JsonResponse({'message': "success"})
        else:
            return JsonResponse({'message': "error"})

@login_required
def remove_analysis(request):
    """Remove the analysis

        Arguments:
        request : http request object

        Comment:
        The user clicked on the "remove analysis" button.
        """
    if request.method == 'POST':
        form = ManageInvestigation(request.POST)
        if form.is_valid():
            case = form.cleaned_data['sa_case_id']
            case_memdump = 'Cases/' + str(case.name)
            try:
                subprocess.check_output(['rm', case_memdump])
            except:
                pass
            case.delete()
            return JsonResponse({'message': "success"})
        else:
            return JsonResponse({'message': "error"})

@login_required
def cancel_analysis(request):
    """Cancel the analysis

        Arguments:
        request : http request object

        Comment:
        When analysis is in progress the user clicked on the "Cancel" button.
        The celery task is canceled.
        """
    if request.method == 'POST':
        form = ManageInvestigation(request.POST)
        if form.is_valid():
            case = form.cleaned_data['sa_case_id']
            case.status = "0"
            task_id = case.taskid
            app.control.revoke(task_id, terminate=True,signal='SIGKILL')
            case.save()
            return JsonResponse({'message': "success"})
        else:
            return JsonResponse({'message': "error"})

@login_required
def reviewinvest(request):
    """Review an analysis

        Arguments:
        request : http request object

        Comment:
        The user requested to review an investigation.
        Get the id of the wanted investigation and send the right context.
        """
    if request.method == 'GET':
        form = ManageInvestigation(request.GET)
        print(request.GET)
        if form.is_valid():
            case = form.cleaned_data['sa_case_id']
            id = case.id
            context = {}
            context['case'] = case

            if case.os_version == "Windows":
                #Forms
                forms ={
                    'dl_hive_form':DownloadHive(),
                    'dl_dump_form': DownloadDump(),
                    'dump_file_form': DumpFile(),
                    'download_file_form': DownloadFile(),
                    'form': DumpMemory(),
                }
                #Models
                models = {
                    'dumps': windows_engine.ProcessDump.objects.filter(case_id = id),
                    'files': windows_engine.FileDump.objects.filter(case_id = id),
                    'ImageSignature' : ImageSignature.objects.get(investigation_id = id),
                    'PsScan': windows_engine.PsScan.objects.filter(investigation_id = id),
                    'PsTree': windows_engine.PsTree.objects.get(investigation_id = id),
                    'CmdLine': windows_engine.CmdLine.objects.filter(investigation_id = id),
                    'Handles': windows_engine.Handles.objects.filter(investigation_id = id),
                    'DllList': windows_engine.DllList.objects.filter(investigation_id = id),
                    'Privs': windows_engine.Privs.objects.filter(investigation_id = id),
                    'Envars': windows_engine.Envars.objects.filter(investigation_id = id),
                    'NetScan': windows_engine.NetScan.objects.filter(investigation_id = id),
                    'NetStat': windows_engine.NetStat.objects.filter(investigation_id = id),
                    'NetGraph' : windows_engine.NetGraph.objects.get(investigation_id = id),
                    'Hashdump': windows_engine.Hashdump.objects.filter(investigation_id = id),
                    'Lsadump':windows_engine.Lsadump.objects.filter(investigation_id = id),
                    'Cachedump': windows_engine.Cachedump.objects.filter(investigation_id = id),
                    'HiveList': windows_engine.HiveList.objects.filter(investigation_id = id),
                    'UserAssist': windows_engine.UserAssist.objects.filter(investigation_id = id),
                    'Timeliner': windows_engine.Timeliner.objects.filter(investigation_id = id),
                    'TimeLineChart': windows_engine.TimeLineChart.objects.get(investigation_id = id),
                    'SkeletonKeyCheck' : windows_engine.SkeletonKeyCheck.objects.filter(investigation_id = id),
                    'Malfind' : windows_engine.Malfind.objects.filter(investigation_id = id),
                    'FileScan' : windows_engine.FileScan.objects.filter(investigation_id = id),
                    'Strings' : windows_engine.Strings.objects.filter(investigation_id = id),
                }
                context.update(forms)
                context.update(models)
            else:
                models = {
                    'ImageSignature' : ImageSignature.objects.get(investigation_id = id),
                    'PsList':linux_engine.PsList.objects.filter(investigation_id = id),
                    'PsTree': linux_engine.PsTree.objects.get(investigation_id = id),
                    'Bash': linux_engine.Bash.objects.filter(investigation_id = id),
                    'ProcMaps': linux_engine.ProcMaps.objects.filter(investigation_id = id),
                    'Lsof': linux_engine.Lsof.objects.filter(investigation_id = id),
                    'TtyCheck': linux_engine.TtyCheck.objects.filter(investigation_id = id),
                    'Elfs': linux_engine.Elfs.objects.filter(investigation_id = id),
                }
                context.update(models)
            return render(request, 'investigations/reviewinvest.html',context)
        else:
            form = ManageInvestigation()
            return render(request,'investigations/investigations.html',{'investigations': UploadInvestigation.objects.all(), 'form': form})

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
            else:
                return reviewinvest(request)
        else:
            return reviewinvest(request)

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
            else:
                messages.add_message(request,messages.ERROR,'You can not download such file.')
        else:
            print(request.POST)
            return None

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
        else:
            print(request.POST)
            return None
