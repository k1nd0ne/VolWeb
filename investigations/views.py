from django.shortcuts import render, redirect
from django.core.serializers import serialize
from django.contrib.auth.decorators import login_required
from .forms import *
from .models import *
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.http import StreamingHttpResponse, FileResponse, JsonResponse
from iocs.models import NewIOC
from .tasks import start_memory_analysis, dump_memory_pid, app, dump_memory_file
from celery.result import AsyncResult
import json, os, uuid, datetime
from os.path import exists


#Investigation view : Manage the created investigations actions (Launch/Delete/Cancel)
@login_required
def investigations(request):
    form = ManageInvestigation()
    return render(request,'investigations/invest.html',{'investigations': UploadInvestigation.objects.all(), 'form': form})


#Create a new investigation based on the ModelForm (see models.py/forms.py)
@login_required
def newinvest(request):
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
                FileFolder.existingPath = fileName
                FileFolder.eof = end
                FileFolder.name = fileName
                FileFolder.uid = uid
                FileFolder.save()
                if int(end):
                    res = JsonResponse({'data':'Uploaded Successfully','existingPath': fileName})
                    activity = Activity()
                    activity.date = datetime.datetime.now().date()
                    activity.count += 1
                    activity.save()
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
                                res = JsonResponse({'data':'Uploaded Successfully','existingPath':model_id.existingPath})
                                try:
                                    activity = Activity.objects.get(date=datetime.datetime.now().date())
                                    activity.count = activity.count + 1
                                except Activity.DoesNotExist:
                                    activity = Activity()
                                    activity.date = datetime.datetime.now().date()
                                    activity.count = 1
                                activity.save()
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


#The start_analysis view : start an analysis
@login_required
def start_analysis(request):
    if request.method == 'POST':
        form = ManageInvestigation(request.POST)
        if form.is_valid():
            id = form.cleaned_data['sa_case_id']
            case = UploadInvestigation.objects.get(pk=id)
            case.status = "1"
            result = start_memory_analysis.delay('Cases/'+str(case.name),case.id)
            case.taskid = result
            case.save()
            return JsonResponse({'message': "success"})
        else:
            return JsonResponse({'message': "error"})


#The remove_analysis view : remove an analysis
@login_required
def remove_analysis(request):
    if request.method == 'POST':
        form = ManageInvestigation(request.POST)
        if form.is_valid():
            id = form.cleaned_data['sa_case_id']
            case = UploadInvestigation.objects.get(pk=id)
            iocs = NewIOC.objects.all()
            for ioc in iocs:
                if str(case.id) in ioc.linkedInvestigationID:
                    ioc.delete()
            os.system('rm Cases/Results/'+str(case.id)+'.json')
            os.system('rm Cases/' + str(case.name))
            case.delete()
            return JsonResponse({'message': "success"})
        else:
            return JsonResponse({'message': "error"})

#The cancel_analysis view : cancel an analysis
@login_required
def cancel_analysis(request):
    if request.method == 'POST':
        form = ManageInvestigation(request.POST)
        if form.is_valid():
            id = form.cleaned_data['sa_case_id']
            case = UploadInvestigation.objects.get(pk=id)
            case.status = "0"
            task_id = case.taskid
            app.control.terminate(task_id)
            case.save()
            return JsonResponse({'message': "success"})
        else:
            return JsonResponse({'message': "error"})


#The reviewinvest view : Pass the memory analysis results to the context
@login_required
def reviewinvest(request):
    if request.method == 'GET':
        form = ManageInvestigation(request.GET)
        if form.is_valid():
            id = form.cleaned_data['sa_case_id']
            case = UploadInvestigation.objects.get(pk=id)
            with open('Cases/Results/'+str(case.id)+'.json') as f:
                context = json.load(f)
            context['case'] = case
            dump_process_form = DumpMemory()
            download_dump_form = DownloadDump()
            dump_file_form = DumpFile()
            download_file_form = DownloadFile()
            context.update({'dl_dump_form': download_dump_form, 'dump_file_form': dump_file_form, 'download_file_form': download_file_form, 'form': dump_process_form, 'dumps':ProcessDump.objects.filter(case_id = id), 'files':FileDump.objects.filter(case_id = id)})
            return render(request, 'investigations/reviewinvest.html',context)
        else:
            form = ManageInvestigation()
            return render(request,'investigations/invest.html',{'investigations': UploadInvestigation.objects.all(), 'form': form})


#The dump_process view : Handle the dump memory requests
@login_required
def dump_process(request):
    if request.method == 'POST':
        form = DumpMemory(request.POST)
        if form.is_valid():
            case_id = form.cleaned_data['case_id']
            pid = form.cleaned_data['pid']
            if len(ProcessDump.objects.filter(pid = pid, case_id = case_id)) > 0:
                return JsonResponse({'message': "exist"})
            task_res = dump_memory_pid.delay(str(case_id),str(pid))
            file_path = task_res.get()
            if file_path != "ERROR":
                #create ProcessDump model :
                Dump = form.save()
                Dump.filename = file_path
                Dump.save()
                dumps = serialize("json",ProcessDump.objects.filter(process_dump_id = Dump.process_dump_id), fields=('pid','filename'))
                return JsonResponse({'message': "success",'dumps': dumps })
            else:
                return JsonResponse({'message': "failed"})
        else:
            return JsonResponse({'message': "error"})


#The dump_process view : Handle the dump memory requests
@login_required
def dump_file(request):
    if request.method == 'POST':
        form = DumpFile(request.POST)
        if form.is_valid():
            case_id = form.cleaned_data['case_id']
            offset = form.cleaned_data['offset']
            if len(FileDump.objects.filter(offset = offset, case_id = case_id)) > 0:
                return JsonResponse({'message': "exist"})
            task_res = dump_memory_file.delay(str(case_id),offset)
            file_path = task_res.get()
            if file_path != "ERROR":
                #create ProcessDump model :
                Dump = form.save()
                Dump.filename = file_path
                Dump.save()
                files = serialize("json",FileDump.objects.filter(file_dump_id = Dump.file_dump_id), fields=('offset','filename'))
                return JsonResponse({'message': "success",'files': files })
            else:
                return JsonResponse({'message': "failed"})
        else:
            return JsonResponse({'message': "error"})

#The download_dump view : Handle the dump download requests
@login_required
def download_dump(request):
    if request.method == 'POST':
        form = DownloadDump(request.POST)
        if form.is_valid():
            dump_id = form.cleaned_data['id']
            Dump = ProcessDump.objects.get(process_dump_id = dump_id)
            file_path = Dump.filename
            try:
                #Checking the extension (need to audit the application to see if R/LFI is possible)
                ext = os.path.basename(file_path).split('.')[-1].lower()
                if ext not in ['py', 'db',  'sqlite3']:
                    response = FileResponse(open('Cases/Results/'+file_path, 'rb'))
                    response['content_type'] = "application/octet-stream"
                    response['Content-Disposition'] = 'attachment; filename=' + os.path.basename(file_path)
                    return response
                else:
                    messages.add_message(request,messages.ERROR,'You can not download such file.')
            except:
                messages.add_message(request,messages.ERROR,'Failed to fetch the requested process')

        else:
            return JsonResponse({'message': "error"})

#The download_file view : Handle the file download requests
@login_required
def download_file(request):
    if request.method == 'POST':
        form = DownloadDump(request.POST)
        if form.is_valid():
            file_id = form.cleaned_data['id']
            Dump = FileDump.objects.get(file_dump_id = file_id)
            file_path = Dump.filename
            try:
                #Checking the extension (need to audit the application to see if R/LFI is possible)
                ext = os.path.basename(file_path).split('.')[-1].lower()
                if ext not in ['py', 'db',  'sqlite3']:
                    response = FileResponse(open('Cases/Results/'+file_path, 'rb'))
                    response['content_type'] = "application/octet-stream"
                    response['Content-Disposition'] = 'attachment; filename=' + os.path.basename(file_path)
                    return response
                else:
                    messages.add_message(request,messages.ERROR,'You can not download such file.')
            except:
                messages.add_message(request,messages.ERROR,'Failed to fetch the requested file')

        else:
            return JsonResponse({'message': "error"})
