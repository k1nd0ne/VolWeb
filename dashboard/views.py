from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from investigations.models import UploadInvestigation, Activity
from iocs.models import NewIOC
from django.contrib.auth import get_user_model
from django.core import serializers

#Dashboard view : Return the dashboard with the latest IOCs and Investigations
@login_required
def dashboard(request):
    User = get_user_model()
    activity = serializers.serialize("json", Activity.objects.all(), fields = ("date", "count"))
    return render(request,'dashboard/dashboard.html',{'Activity': activity, 'Users':User.objects.all(),'investigations':UploadInvestigation.objects.all().count(), 'iocs':NewIOC.objects.all().count()})
