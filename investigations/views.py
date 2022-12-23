import os, subprocess, uuid
import windows_engine.models as windows_engine
import linux_engine.models as linux_engine
from .tasks import start_memory_analysis, app
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth import get_user_model
from django.shortcuts import render, redirect
from django.core.serializers import serialize
from celery.result import AsyncResult
from iocs.models import IOC
from os.path import exists
from investigations.models import *
from symbols.models import Symbols
from investigations.forms import *


@login_required
def investigations(request):
    """Investigation dashboard

    Arguments:
    request : http request object

    Comment:
    First entry point to visualize all of the investigations
    """
    return render(request, 'investigations/investigations.html', {'investigations': UploadInvestigation.objects.all()})


@login_required
def custom_invest(request, pk):    
    """Custom an investigation

        Arguments:
        request : http request object

        Comment:
        Get the investigation and fill the different field.
        """
    investigation = UploadInvestigation.objects.get(pk=pk)
    if request.method == 'GET':
        custom_form = CustomInvestigation(instance=investigation)
    if request.method == 'POST':
        form = CustomInvestigation(request.POST, instance=investigation)
        if form.is_valid():
            investigation.save()
            return redirect('/investigations/')
        else:
            print(form.errors)
    User = get_user_model()
    return render(request, 'investigations/custom_invest.html',{'form':custom_form})


@login_required
def new_invest(request):
    """Create a new investigation

            Arguments:
            request : http request object

            Comment:
            Handle the file upload chunk by chunk.
            Create the investigation if the upload is successful.
            """
    if request.method == 'POST':
        form = UploadFileForm(request.POST)
        if form.is_valid():
            title = form.cleaned_data['title']
            os_version = form.cleaned_data['os_version']
            investigators = form.cleaned_data['investigators']
            description = form.cleaned_data['description']
            file = request.FILES['file'].read()
            file_name = form.cleaned_data['name']
            existing_path = request.POST['existing_path']
            end = request.POST['eof']
            next_slice = request.POST['nextSlice']
        else:
            return JsonResponse({'data': form.errors})
        if file == "" or file_name == "" or existing_path == "" or end == "" or next_slice == "":
            return JsonResponse({'data': 'Invalid Request'})
        else:
            if existing_path == 'null':
                uid = uuid.uuid4()
                file_name = str(uid) + "_" + file_name
                path = 'Cases/' + file_name
                with open(path, 'wb+') as destination:
                    destination.write(file)
                file_folder = UploadInvestigation()
                file_folder.title = title
                file_folder.os_version = os_version
                file_folder.investigators = investigators
                file_folder.description = description
                file_folder.status = "-1"
                file_folder.percentage = "0"
                file_folder.existingPath = file_name
                file_folder.eof = end
                file_folder.name = file_name
                file_folder.uid = uid
                file_folder.save()
                if int(end):
                    res = JsonResponse({'data': 'Uploaded Successfully', 'existing_path': file_name})
                    file_folder.status = "0"
                else:
                    res = JsonResponse({'existing_path': file_name})
                return res
            else:
                path = 'Cases/' + existing_path
                model_id = UploadInvestigation.objects.get(existingPath=existing_path)
                if model_id.name == existing_path:
                    if not model_id.eof:
                        with open(path, 'ab+') as destination:
                            destination.write(file)
                            if int(end):
                                model_id.eof = int(end)
                                model_id.status = "0"
                                model_id.save()
                                model_id.update_activity()
                                res = JsonResponse(
                                    {'data': 'Uploaded Successfully', 'existing_path': model_id.existingPath})
                            else:
                                res = JsonResponse({'existing_path': model_id.existingPath})
                                return res
                    else:
                        res = JsonResponse({'data': 'EOF found. Invalid request'})
                        return res
                else:
                    res = JsonResponse({'data': 'No such file exists in the existing_path'})
                    return res
    form = UploadFileForm()
    User = get_user_model()
    return render(request, 'investigations/new_invest.html',
                  {'form': form, 'Users': User.objects.filter(is_superuser=False)})


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
                response = serialize('python', [u], ensure_ascii=False,
                                     fields=('title', 'name', 'investigators', 'description', 'status', 'percentage', 'os_version'))
            except ObjectDoesNotExist:
                response = {'message': 'N/A'}
            try:
                i = IOC.objects.filter(linkedInvestigation=id)
                iocs = serialize('python', list(i), ensure_ascii=False, fields=('value', 'context'))
            except ObjectDoesNotExist:
                iocs = {'message': 'N/A'}
            try:
                u = UploadInvestigation.objects.get(pk=id)
                s = u.linked_isf
                if s:
                    isf = serialize('json', [s, ], fields=('name', 'description'))
                else:
                    isf = {'message': 'N/A'}

            except ObjectDoesNotExist:
                isf = {'message': 'N/A'}
            return JsonResponse({'message': "success", 'result': response, 'iocs': iocs, 'isf': isf})
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
            result = start_memory_analysis.delay('Cases/' + str(case.name), case.id)
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
            app.control.revoke(task_id, terminate=True, signal='SIGKILL')
            case.save()
            return JsonResponse({'message': "success"})
        else:
            return JsonResponse({'message': "error"})


@login_required
def review_invest(request):
    """Review an analysis

        Arguments:
        request : http request object

        Comment:
        The user requested to review an investigation.
        Get the id of the wanted investigation and send the right context.
        """
    if request.method == 'GET':
        form = ManageInvestigation(request.GET)
        if form.is_valid():
            case = form.cleaned_data['sa_case_id']
            id = case.id
            context = {'case': case}

            if case.os_version == "Windows":
                # Forms
                forms = {
                    'dl_hive_form': DownloadHive(),
                }
                # Models
                models = {
                    'dumps': windows_engine.ProcessDump.objects.filter(case_id=id),
                    'files': windows_engine.FileDump.objects.filter(case_id=id),
                    'ImageSignature': ImageSignature.objects.get(investigation_id=id),
                    'PsScan': windows_engine.PsScan.objects.filter(investigation_id=id),
                    'PsTree': windows_engine.PsTree.objects.get(investigation_id=id),
                    'CmdLine': windows_engine.CmdLine.objects.filter(investigation_id=id),
                    'Handles': windows_engine.Handles.objects.filter(investigation_id=id),
                    'DllList': windows_engine.DllList.objects.filter(investigation_id=id),
                    'Privs': windows_engine.Privs.objects.filter(investigation_id=id),
                    'Envars': windows_engine.Envars.objects.filter(investigation_id=id),
                    'NetScan': windows_engine.NetScan.objects.filter(investigation_id=id),
                    'NetStat': windows_engine.NetStat.objects.filter(investigation_id=id),
                    'NetGraph': windows_engine.NetGraph.objects.get(investigation_id=id),
                    'Hashdump': windows_engine.Hashdump.objects.filter(investigation_id=id),
                    'Lsadump': windows_engine.Lsadump.objects.filter(investigation_id=id),
                    'Cachedump': windows_engine.Cachedump.objects.filter(investigation_id=id),
                    'HiveList': windows_engine.HiveList.objects.filter(investigation_id=id),
                    'UserAssist': windows_engine.UserAssist.objects.filter(investigation_id=id),
                    'Timeliner': windows_engine.Timeliner.objects.filter(investigation_id=id),
                    'TimeLineChart': windows_engine.TimeLineChart.objects.get(investigation_id=id),
                    'SkeletonKeyCheck': windows_engine.SkeletonKeyCheck.objects.filter(investigation_id=id),
                    'Malfind': windows_engine.Malfind.objects.filter(investigation_id=id),
                    'FileScan': windows_engine.FileScan.objects.filter(investigation_id=id),
                    'Strings': windows_engine.Strings.objects.filter(investigation_id=id),
                }
                context.update(forms)
                context.update(models)
            else:
                models = {
                    'ImageSignature': ImageSignature.objects.get(investigation_id=id),
                    'PsList': linux_engine.PsList.objects.filter(investigation_id=id),
                    'PsTree': linux_engine.PsTree.objects.get(investigation_id=id),
                    'Bash': linux_engine.Bash.objects.filter(investigation_id=id),
                    'ProcMaps': linux_engine.ProcMaps.objects.filter(investigation_id=id),
                    'Lsof': linux_engine.Lsof.objects.filter(investigation_id=id),
                    'TtyCheck': linux_engine.TtyCheck.objects.filter(investigation_id=id),
                    'Elfs': linux_engine.Elfs.objects.filter(investigation_id=id),
                }
                context.update(models)
            return render(request, 'investigations/review_invest.html', context)
        else:
            return render(request, 'investigations/investigations.html',
                          {'investigations': UploadInvestigation.objects.all()})
