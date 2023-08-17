from django.shortcuts import render
from django.contrib.auth.decorators import login_required

# Create your views here.
@login_required
def evidences(request):
    """Load evidence page

        Arguments:
        request : http request object

        Comments:
        Display the evidences page
        """
    return render(request, 'evidences/evidences.html')