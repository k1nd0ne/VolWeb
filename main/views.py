from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model


@login_required
def home(request):
    """Load home page

        Arguments:
        request : http request object

        Comments:
        Display the home page and pass the users/activities/analysis/
        """
    User = get_user_model()
    return render(request, 'main/home.html',{'Users': User.objects.all()})