from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .forms import *
from .models import *
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.http import HttpResponse, Http404, StreamingHttpResponse, FileResponse, JsonResponse
from iocs.models import NewIOC
from .tasks import start_memory_analysis, dump_memory_pid
from celery.result import AsyncResult
from .tasks import app, dump_memory_pid
import json, os, uuid, datetime


#Global context variable used by the volatility_script.py to store results and give it back to the investigation review view.
context = {}


#Investigation view : Manage the created investigations actions (Launch/Delete/Cancel)
@login_required
def investigations(request):
    if request.method == 'POST':
        form = ManageInvestigation(request.POST)
        if request.is_ajax():
            if form.is_valid():
                action = form.cleaned_data['action']
                id = form.cleaned_data['id']
                case = UploadInvestigation.objects.get(pk=id)
                #Launch the volatility_script
                if action == "1":
                    case.status = "1"
                    result = start_memory_analysis.delay('Cases/'+str(case.name),case.id)
                    print(type(result))
                    case.taskid = result
                    case.save()
                #Remove the memory dump
                elif action == "0":
                    iocs = NewIOC.objects.all()
                    for ioc in iocs:
                        if str(case.id) in ioc.linkedInvestigationID:
                            ioc.delete()
                    os.system('rm Cases/Results/'+str(case.id)+'.json')
                    os.system('rm Cases/' + str(case.name))
                    case.delete()
                #Cancel the memory analysis
                elif action == "2":
                    case.status = "0"
                    task_id = case.taskid
                    app.control.terminate(task_id)
                    case.save()
                #Review the investigation (Load the json result file into the context for the 'reviewinvest' view)
                elif action == "3":
                    global context
                    with open('Cases/Results/'+str(case.id)+'.json') as f:
                        context = json.load(f)
                    context['case'] = case
                return JsonResponse({'message': 'true'})
            else:
                return JsonResponse({'message': 'false'})
    else:
        #Display all the investigations and the action form
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


#The reviewinvest view : Handle the dump memory request and pass the memory analysis results to the context
@login_required
def reviewinvest(request):
    global context
    if request.method == 'POST':
        form = DumpMemory(request.POST)
        if form.is_valid():
            case_id = form.cleaned_data['id']
            pid = form.cleaned_data['pid']
            task_res = dump_memory_pid.delay(case_id,str(pid))
            file_path = task_res.get()
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
            messages.add_message(request,messages.ERROR,'The PID is not correct')
    form = DumpMemory()
    context.update({'form': form})
    return render(request, 'investigations/reviewinvest.html',context)
