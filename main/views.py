from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model
from django.http import JsonResponse
from VolWeb.keyconfig import Secrets

@login_required
def home(request):
    """Load home page

    Arguments:
    request : http request object

    Comments:
    Display the home page and pass the users/activities/analysis/
    """
    User = get_user_model()
    return render(request, "main/home.html", {"Users": User.objects.all()})


def websocket_url(request):
    protocol = 'wss' if request.is_secure() else 'ws'
    ws_url = f"{protocol}://{Secrets.WEBSOCKET_HOST}"
    return JsonResponse({'websocket_url': ws_url})
