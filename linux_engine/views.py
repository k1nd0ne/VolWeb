from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse
from django.core.serializers import json
from django.apps import apps
from .models import *
from .tasks import compute_procmaps
from .forms import *
from .report import report



@login_required
def get_procmaps(request):
    """Get ProcMaps from a PID

    Arguments:
    request : http request object

    Comment:
    The user requested to watch the ProcMaps linked to a process. 
    If the ProcMaps are already calculated, then the result is fetch
    Else, volatility3 will calculate them using celery.
    """
    if request.method == 'GET':

        form = GetArtifacts(request.GET)
        if form.is_valid():
            case = form.cleaned_data['case']
            id = case.id
            pid = form.cleaned_data['pid']
            json_serializer = json.Serializer()
            # Check if the ProcMaps are not already computed
            procmaps = ProcMaps.objects.filter(investigation_id=id, PID=pid)
            if len(procmaps)>0: 
                #Already computed we display the result
                artifacts = {
                    'ProcMaps': json_serializer.serialize(procmaps),
                }
            else:
                #start a task with celery to compute the procmaps and send the result.
                task_res = compute_procmaps.delay(str(id), str(pid))
                res =  task_res.get()
                if res != "OK":
                    return JsonResponse({'message': "error"})
                else:
                    artifacts = {
                        'ProcMaps': json_serializer.serialize(ProcMaps.objects.filter(investigation_id=id, PID=pid)),
                    }
            return JsonResponse({'message': "success", 'artifacts': artifacts})
    
    return JsonResponse({'message': "error"})

@login_required
def lin_report(request):
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
def lin_tag(request):
    """
    Tag a Linux artifact
    """
    if request.method == 'POST':
        form = Tag(request.POST)
        if form.is_valid():
            item = apps.get_model("linux_engine", form.cleaned_data['plugin_name']).objects.get(
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
def get_l_artifacts(request):
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
                'Bash': json_serializer.serialize(Bash.objects.filter(investigation_id=id, PID=pid)),
                'Elfs': json_serializer.serialize(Elfs.objects.filter(investigation_id=id, PID=pid)),
                'Lsof': json_serializer.serialize(Lsof.objects.filter(investigation_id=id, PID=pid)),
                'ProcMaps': json_serializer.serialize(ProcMaps.objects.filter(investigation_id=id, PID=pid)),
                'PsAux': json_serializer.serialize(PsAux.objects.filter(investigation_id=id, PID=pid)),
            }
            return JsonResponse({'message': "success", 'artifacts': artifacts})
    return JsonResponse({'message': "error"})


