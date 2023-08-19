from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from evidences.forms import EvidenceForm
from rest_framework.views import APIView
from rest_framework import permissions
from rest_framework import status
from evidences.models import Evidence
from rest_framework.response import Response
from evidences.serializers import EvidenceSerializer

# Create your views here.
@login_required
def evidences(request):
    """Load evidence page

        Arguments:
        request : http request object

        Comments:
        Display the evidences page
        """
    evidence_form =  EvidenceForm() 
    return render(request, 'evidences/evidences.html',{'evidence_form': evidence_form})

class CaseEvidenceApiView(APIView):
    # add permission to check if user is authenticated
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, case_id, *args, **kwargs):
        '''
        List all the evidence for given requested user
        '''
        evidences = Evidence.objects.filter(dump_linked_case=case_id)
        serializer = EvidenceSerializer(evidences,many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)




class EvidenceAPIView(APIView):
    # add permission to check if user is authenticated
    permission_classes = [permissions.IsAuthenticated]

    # 1. List all
    def get(self, request, *args, **kwargs):
        '''
        List all the evidence for given requested user
        '''
        evidences = Evidence.objects.all()
        serializer = EvidenceSerializer(evidences,many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    # 2. Create
    def post(self, request, *args, **kwargs):
        '''
        Create an evidence
        '''
        data = {
            'dump_name' : request.data.get('dump_name'),
            'dump_os': request.data.get('dump_os'), 
            'dump_linked_case': request.data.get('dump_linked_case'), 
        }
        serializer = EvidenceSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EvidenceDetailApiView(APIView):
    # add permission to check if user is authenticated
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self, dump_id):
        '''
        Helper method to get the object with given dump_id
        '''
        try:
            return Evidence.objects.get(dump_id=dump_id)
        except Evidence.DoesNotExist:
            return None