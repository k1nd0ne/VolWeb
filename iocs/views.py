from django.shortcuts import render, redirect
from investigations.models import UploadInvestigation
from django.contrib.auth.decorators import login_required
from .forms import *
from .models import IOC
from django.http import JsonResponse

customize_context = {}

@login_required
def iocs(request):
    """The iocs dashboard

        Arguments:
        request : http request object

        Comment: Display all of the iocs
        """
    form = ManageIOC()
    return render(request,'iocs/iocs.html',{'iocs':IOC.objects.all(), 'investigations':UploadInvestigation.objects.all(), 'form':form})

@login_required
def newioc(request):
    """Create a new string base IOC

        Arguments:
        request : http request object

        Comment: Create a new IOC if the form is correct.
        """
    if request.method == "POST":
        form = NewIOCForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('/iocs/')
    form = NewIOCForm()
    return render(request,'iocs/newioc.html',{'form': form, 'investigations':UploadInvestigation.objects.all()})

@login_required
def customioc(request):
    """Modify an ioc

        Arguments:
        request : http request object

        Comments:
        GET : Load the form page with intanced fields.
        POST : Apply the modifications
        """
    if request.method == 'GET':
        form = ManageIOC(request.GET)
        if form.is_valid():
            id = form.cleaned_data['ioc_id']
            ioc_record = IOC.objects.get(pk=id)
            custom_form = SaveCustomIOC(instance=ioc_record)
            return render(request,'iocs/customioc.html',{'form': custom_form, 'ioc_id':id, 'investigations':UploadInvestigation.objects.all()})
    if request.method == 'POST':
        form = SaveCustomIOC(request.POST)
        if form.is_valid():
            ioc_record = IOC.objects.get(pk=form.cleaned_data['ioc_id'])
            ioc_record.name = form.cleaned_data['name']
            ioc_record.context = form.cleaned_data['context']
            ioc_record.value = form.cleaned_data['value']
            ioc_record.linkedInvestigation = form.cleaned_data['linkedInvestigation']
            ioc_record.save()
            return redirect('/iocs/')


@login_required
def deleteioc(request):
    """Delete an ioc

        Arguments:
        request : http request object

        Comments:
        Delete the IOC selected by the user.
        """
    if request.method == "POST":
        form = ManageIOC(request.POST)
        if form.is_valid():
            id = form.cleaned_data['ioc_id']
            # Delete the ioc
            ioc  = IOC.objects.get(pk=id)
            ioc.delete()
            return redirect('/iocs/')
        else:
            #Return a error django message (need to setup toast)
            form = NewIOCForm()
            return render(request,'iocs/newioc.html',{'form': form, 'investigations':UploadInvestigation.objects.all()})
