from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from windows_engine.models import PsTree
from evidences.models import Evidence
from windows_engine.serializers import PsTreeSerializer
from rest_framework.views import APIView
from rest_framework import permissions
from rest_framework import status
from rest_framework.response import Response

@login_required
def review(request, dump_id):
    evidence = Evidence.objects.get(dump_id=dump_id)
    return render(request, 'windows_engine/review_evidence.html',{'evidence':evidence})


class PsTreeApiView(APIView):
    # add permission to check if user is authenticated
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, dump_id, *args, **kwargs):
        '''
        Give the requested PSTree.
        '''
        tree = PsTree.objects.filter(evidence_id=dump_id)
        serializer = PsTreeSerializer(tree,many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)