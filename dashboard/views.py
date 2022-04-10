from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from investigations.models import UploadInvestigation, Activity
from iocs.models import IOC
from django.contrib.auth import get_user_model
from django.core import serializers

#Dashboard view : Return the dashboard with the latest IOCs and Investigations
@login_required
def dashboard(request):
    """Load the dashboard

        Arguments:
        request : http request object

        Comments:
        Display the dashboard and pass the users/activities/analysis/iocs
        """
    User = get_user_model()
    activity = serializers.serialize("json", Activity.objects.all(), fields = ("date", "count"))
    return render(request,'dashboard/dashboard.html',{'Activity': activity, 'Users':User.objects.filter(is_superuser = False),'investigations':UploadInvestigation.objects.all().count(), 'iocs':IOC.objects.all().count()})
