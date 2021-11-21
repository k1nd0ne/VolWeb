from django.shortcuts import render, redirect
from investigations.models import UploadInvestigation
from django.contrib.auth.decorators import login_required
from .forms import NewIOCForm, ManageIOC
from .models import NewIOC
from django.http import JsonResponse

customize_context = {}

@login_required
def iocs(request):
    if request.method == "POST":
        form = ManageIOC(request.POST)
        if request.is_ajax():
            if form.is_valid():
                action = form.cleaned_data['action']
                id = form.cleaned_data['id']
                ioc = NewIOC.objects.get(pk=id)
                if action == "0":
                    ioc.delete()
                else:
                    global customize_context
                    customize_context['ioc_id'] = id
                return JsonResponse({'message': 'true'})
            else:
                print('Error')
                return JsonResponse({'message': 'false'})
    else:
        form = ManageIOC()
    return render(request,'iocs/iocs.html',{'iocs':NewIOC.objects.all(), 'investigations':UploadInvestigation.objects.all(), 'form':form})
@login_required
def newioc(request):
    if request.method == "POST":
        form = NewIOCForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('/iocs/')
    form = NewIOCForm()
    return render(request,'iocs/newioc.html',{'form': form, 'investigations':UploadInvestigation.objects.all()})

@login_required
def customioc(request):
    global customize_context
    ioc_record = NewIOC.objects.get(pk=customize_context['ioc_id'])
    if request.method == 'POST':
        form = NewIOCForm(request.POST)
        if form.is_valid():
            ioc_record.name  = form.cleaned_data['name']
            ioc_record.value  = form.cleaned_data['value']
            ioc_record.linkedInvestigation  = form.cleaned_data['linkedInvestigation']
            ioc_record.linkedInvestigationID  = form.cleaned_data['linkedInvestigationID']
            ioc_record.save()
            return redirect('/iocs/')
        else:
            message = "Please check fill the field(s) : "
            for i in form.errors:
                message += i+" "
                print(i,'\n')
            return JsonResponse({'message': message})
    else:
        form = NewIOCForm(instance=ioc_record)
    return render(request,'iocs/customioc.html',{'form':form,'investigations':UploadInvestigation.objects.all()})

