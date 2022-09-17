from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse
from django.apps import apps
from .forms import *
from .report import report
@login_required
def lin_report(request):
    """
    Generate the windows report
    """
    form = ReportForm(request.POST)
    if form.is_valid():
            case = form.cleaned_data['case_id']
            html, text = report(case)
            return JsonResponse({'message': "success",'html':html, 'text':text})
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
            item = apps.get_model("linux_engine", form.cleaned_data['plugin_name']).objects.get(id=form.cleaned_data['artifact_id'])
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
