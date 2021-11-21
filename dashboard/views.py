from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from investigations.models import UploadInvestigation
from iocs.models import NewIOC
from django.contrib.auth import get_user_model

#Dashboard view : Return the dashboard with the latest IOCs and Investigations
@login_required
def dashboard(request):
    User = get_user_model()
    return render(request,'dashboard/dashboard.html',{'Users':User.objects.all(),'investigations':UploadInvestigation.objects.all().count(), 'iocs':NewIOC.objects.all().count()})

