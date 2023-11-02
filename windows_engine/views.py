from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from windows_engine.models import *
from evidences.models import Evidence
from windows_engine.serializers import *
from rest_framework.views import APIView
from rest_framework import permissions
from rest_framework import status
from rest_framework.response import Response

@login_required
def review(request, dump_id):
    evidence = Evidence.objects.get(dump_id=dump_id)
    return render(request, 'windows_engine/review_evidence.html',{'evidence':evidence})

def process(request, dump_id, process_id):
        return render(request, 'windows_engine/review_process.html', {'evidence':dump_id, 'pid':process_id})

class PsTreeApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, dump_id, *args, **kwargs):
        '''
        Give the requested PSTree.
        '''
        tree = PsTree.objects.filter(evidence_id=dump_id)
        serializer = PsTreeSerializer(tree,many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class TimelineChartApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, dump_id, *args, **kwargs):
        '''
        Give the requested Timeline.
        '''
        timeline = TimeLineChart.objects.filter(evidence_id=dump_id)
        serializer = TimelineChartSerializer(timeline,many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class TimelineDataApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, dump_id, timestamp, *args, **kwargs):
        '''
        Give the requested Timeline Date from the timestamp.
        '''
        data = Timeliner.objects.filter(evidence_id=dump_id, CreatedDate=timestamp)
        serializer = TimelineDataSerializer(data,many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class CmdLineApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request, dump_id, pid, *args, **kwargs):
        '''
        Give the requested cmdline from the pid.
        '''
        data = CmdLine.objects.filter(evidence_id=dump_id, PID=pid)
        serializer = CmdLineSerializer(data,many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class GetSIDsApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request, dump_id, pid, *args, **kwargs):
        '''
        Give the requested cmdline from the pid.
        '''
        data = GetSIDs.objects.filter(evidence_id=dump_id, PID=pid)
        serializer = GetSIDsSerializer(data,many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class PrivsApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request, dump_id, pid, *args, **kwargs):
        '''
        Give the requested cmdline from the pid.
        '''
        data = Privs.objects.filter(evidence_id=dump_id, PID=pid)
        serializer = PrivsSerializer(data,many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class EnvarsApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request, dump_id, pid, *args, **kwargs):
        '''
        Give the requested cmdline from the pid.
        '''
        data = Envars.objects.filter(evidence_id=dump_id, PID=pid)
        serializer = EnvarsSerializer(data,many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class DllListApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request, dump_id, pid, *args, **kwargs):
        '''
        Give the requested cmdline from the pid.
        '''
        data = DllList.objects.filter(evidence_id=dump_id, PID=pid)
        serializer = DllListSerializer(data,many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class SessionsApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request, dump_id, pid, *args, **kwargs):
        '''
        Give the requested cmdline from the pid.
        '''
        data = Sessions.objects.filter(evidence_id=dump_id, ProcessID=pid)
        serializer = SessionsSerializer(data,many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)