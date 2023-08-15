from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import permissions
from main.models import Case
from main.serializers import CaseSerializer
#from main.forms import CaseForm 

class CaseApiView(APIView):
    # add permission to check if user is authenticated
    permission_classes = [permissions.IsAuthenticated]

    # 1. List all
    def get(self, request, *args, **kwargs):
        '''
        List all the cases for given requested user
        '''
        cases = Case.objects.all()
        serializer = CaseSerializer(cases, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    # 2. Create
    def post(self, request, *args, **kwargs):
        '''
        Create the Case with given case data
        '''
        data = {
            'case_name': request.data.get('case_name'), 
            'case_description': request.data.get('case_description'), 
            'linked_users': request.data.get('linked_users'), 
        }
        serializer = CaseSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



@login_required
def home(request):
    """Load home page

        Arguments:
        request : http request object

        Comments:
        Display the home page and pass the users/activities/analysis/
        """
    User = get_user_model()
    return render(request, 'main/home.html',{'Users': User.objects.filter(is_superuser=False)})


@login_required
def cases(request):
    """Load home page

        Arguments:
        request : http request object

        Comments:
        Display the home page and pass the users/activities/analysis/
        """
    return render(request, 'main/cases.html')