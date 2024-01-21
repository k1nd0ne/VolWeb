from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from windows_engine.tasks import compute_handles, dump_process_pslist, dump_process_memmap, dump_file
from windows_engine.models import *
from evidences.models import Evidence
from django_celery_results.models import TaskResult 
from windows_engine.serializers import *
from rest_framework.views import APIView
from rest_framework import permissions
from rest_framework import status
from rest_framework.response import Response


@login_required
def review(request, dump_id):
    evidence = Evidence.objects.get(dump_id=dump_id)
    return render(
        request, "windows_engine/review_evidence.html", {"evidence": evidence}
    )


class PsTreeApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self, dump_id):
        try:
            return PsTree.objects.get(evidence_id=dump_id)
        except PsTree.DoesNotExist:
            return None


    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested PSTree.
        """
        data = self.get_object(dump_id)
        serializer = PsTreeSerializer(data)
        return Response(serializer.data, status=status.HTTP_200_OK)


class TimelineChartApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get_object(self, dump_id):
        try:
            return TimeLineChart.objects.get(evidence_id=dump_id)
        except TimeLineChart.DoesNotExist:
            return None

    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested TimelineChart.
        """
        data = self.get_object(dump_id)
        serializer = TimelineChartSerializer(data)
        return Response(serializer.data, status=status.HTTP_200_OK)


class TimelineDataApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self, dump_id):
        try:
            return Timeliner.objects.get(evidence_id=dump_id)
        except Timeliner.DoesNotExist:
            return None

    def get(self, request, dump_id, timestamp, *args, **kwargs):
        """
        Give the requested Timeline Date from the timestamp.
        """
        data = self.get_object(dump_id)
        if data:
            filtered_data = [d for d in data.artefacts if d['Created Date'] == timestamp]
        return Response(filtered_data, status=status.HTTP_200_OK)

    def patch(self, request, dump_id, artifact_id, tag, *args, **kwargs):
        try:
            instance = Timeliner.objects.get(evidence_id=dump_id, pk=artifact_id)
        except Timeliner.DoesNotExist:
            return Response(
                {"error": "Object not found."}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = TimelineDataSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CmdLineApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get_object(self, dump_id):
        try:
            return CmdLine.objects.get(evidence_id=dump_id)
        except CmdLine.DoesNotExist:
            return None

    def get(self, request, dump_id, pid, *args, **kwargs):
        """
        Give the requested cmdline from the pid.
        """
        data = self.get_object(dump_id)
        if data:
            filtered_data = [d for d in data.artefacts if d['PID'] == pid]
        return Response(filtered_data, status=status.HTTP_200_OK)

class GetSIDsApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self, dump_id):
        try:
            return GetSIDs.objects.get(evidence_id=dump_id)
        except GetSIDs.DoesNotExist:
            return None

    def get(self, request, dump_id, pid, *args, **kwargs):
        """
        Give the requested cmdline from the pid.
        """
        data = self.get_object(dump_id)
        if data:
            filtered_data = [d for d in data.artefacts if d['PID'] == pid]
        return Response(filtered_data, status=status.HTTP_200_OK)

    def patch(self, request, dump_id, artifact_id, tag, *args, **kwargs):
        try:
            instance = GetSIDs.objects.get(evidence_id=dump_id, pk=artifact_id)
        except GetSIDs.DoesNotExist:
            return Response(
                {"error": "Object not found."}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = GetSIDsSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PrivsApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self, dump_id):
        try:
            return Privs.objects.get(evidence_id=dump_id)
        except Privs.DoesNotExist:
            return None
        
    def get(self, request, dump_id, pid, *args, **kwargs):
        """
        Give the requested cmdline from the pid.
        """
        data = self.get_object(dump_id)
        if data:
            filtered_data = [d for d in data.artefacts if d['PID'] == pid]
        return Response(filtered_data, status=status.HTTP_200_OK)

    def patch(self, request, dump_id, artifact_id, tag, *args, **kwargs):
        try:
            instance = Privs.objects.get(evidence_id=dump_id, pk=artifact_id)
        except Privs.DoesNotExist:
            return Response(
                {"error": "Object not found."}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = PrivsSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EnvarsApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self, dump_id):
        try:
            return Envars.objects.get(evidence_id=dump_id)
        except Envars.DoesNotExist:
            return None
        
    def get(self, request, dump_id, pid, *args, **kwargs):
        """
        Give the requested cmdline from the pid.
        """
        data = self.get_object(dump_id)
        if data:
            filtered_data = [d for d in data.artefacts if d['PID'] == pid]
        return Response(filtered_data, status=status.HTTP_200_OK)

    def patch(self, request, dump_id, artifact_id, tag, *args, **kwargs):
        try:
            instance = Envars.objects.get(evidence_id=dump_id, pk=artifact_id)
        except Envars.DoesNotExist:
            return Response(
                {"error": "Object not found."}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = EnvarsSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DllListApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get_object(self, dump_id):
        try:
            return DllList.objects.get(evidence_id=dump_id)
        except DllList.DoesNotExist:
            return None
        
    def get(self, request, dump_id, pid, *args, **kwargs):
        """
        Give the requested cmdline from the pid.
        """
        data = self.get_object(dump_id)
        if data:
            filtered_data = [d for d in data.artefacts if d['PID'] == pid]
        return Response(filtered_data, status=status.HTTP_200_OK)

    def patch(self, request, dump_id, artifact_id, tag, *args, **kwargs):
        try:
            instance = DllList.objects.get(evidence_id=dump_id, pk=artifact_id)
        except DllList.DoesNotExist:
            return Response(
                {"error": "Object not found."}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = DllListSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SessionsApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get_object(self, dump_id):
        try:
            return Sessions.objects.get(evidence_id=dump_id)
        except Sessions.DoesNotExist:
            return None
        
    def get(self, request, dump_id, pid, *args, **kwargs):
        """
        Give the requested session from the pid.
        """
        data = self.get_object(dump_id)
        if data:
            filtered_data = [d for d in data.artefacts if d['Process ID'] == pid]
        return Response(filtered_data, status=status.HTTP_200_OK)

    def patch(self, request, dump_id, artifact_id, tag, *args, **kwargs):
        try:
            instance = Sessions.objects.get(evidence_id=dump_id, pk=artifact_id)
        except Sessions.DoesNotExist:
            return Response(
                {"error": "Object not found."}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = SessionsSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class NetStatApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get_object(self, dump_id):
        try:
            return NetStat.objects.get(evidence_id=dump_id)
        except NetStat.DoesNotExist:
            return None
    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested netstat data
        """
        data = self.get_object(dump_id)
        serializer = NetStatSerializer(data)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, dump_id, artifact_id, tag, *args, **kwargs):
        try:
            instance = NetStat.objects.get(evidence_id=dump_id, pk=artifact_id)
        except NetStat.DoesNotExist:
            return Response(
                {"error": "Object not found."}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = NetStatSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class NetScanApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get_object(self, dump_id):
        try:
            return NetScan.objects.get(evidence_id=dump_id)
        except NetScan.DoesNotExist:
            return None
    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested netscan data
        """
        data = self.get_object(dump_id)
        serializer = NetScanSerializer(data)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, dump_id, artifact_id, tag, *args, **kwargs):
        try:
            instance = NetScan.objects.get(evidence_id=dump_id, pk=artifact_id)
        except NetScan.DoesNotExist:
            return Response(
                {"error": "Object not found."}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = NetScanSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class NetGraphApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested netgraph data
        """
        data = NetGraph.objects.filter(evidence_id=dump_id)
        serializer = NetGraphSerializer(data, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class SvcScanApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get_object(self, dump_id):
        try:
            return SvcScan.objects.get(evidence_id=dump_id)
        except SvcScan.DoesNotExist:
            return None
        
    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested services data
        """
        data = self.get_object(dump_id)
        serializer = SvcScanSerializer(data)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def patch(self, request, dump_id, artifact_id, tag, *args, **kwargs):
        try:
            instance = SvcScan.objects.get(evidence_id=dump_id, pk=artifact_id)
        except SvcScan.DoesNotExist:
            return Response(
                {"error": "Object not found."}, status=status.HTTP_404_NOT_FOUND
            )
        serializer = SvcScanSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class HashdumpApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get_object(self, dump_id):
        try:
            return Hashdump.objects.get(evidence_id=dump_id)
        except Hashdump.DoesNotExist:
            return None
    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested Hashdump data
        """
        data = self.get_object(dump_id)
        serializer = HashdumpSerializer(data)
        return Response(serializer.data, status=status.HTTP_200_OK)


class CachedumpApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get_object(self, dump_id):
        try:
            return Cachedump.objects.get(evidence_id=dump_id)
        except Cachedump.DoesNotExist:
            return None
    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested Cachedump data
        """
        data = self.get_object(dump_id)
        serializer = CachedumpSerializer(data)
        return Response(serializer.data, status=status.HTTP_200_OK)


class LsadumpApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self, dump_id):
        try:
            return Lsadump.objects.get(evidence_id=dump_id)
        except Lsadump.DoesNotExist:
            return None
        
    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested Lsadump data
        """
        data = self.get_object(dump_id)
        serializer = LsadumpSerializer(data)
        return Response(serializer.data, status=status.HTTP_200_OK)

class MalfindApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self, dump_id):
        try:
            return Malfind.objects.get(evidence_id=dump_id)
        except Malfind.DoesNotExist:
            return None

    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested malfind data
        """
        data = self.get_object(dump_id)
        serializer = MalfindSerializer(data)
        return Response(serializer.data, status=status.HTTP_200_OK)


class LdrModulesApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self, dump_id):
        try:
            return LdrModules.objects.get(evidence_id=dump_id)
        except LdrModules.DoesNotExist:
            return None
        
    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested ldrmodules data
        """
        data = self.get_object(dump_id)
        serializer = LdrModulesSerializer(data)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, dump_id, artifact_id, tag, *args, **kwargs):
        try:
            instance = LdrModules.objects.get(evidence_id=dump_id, pk=artifact_id)
        except LdrModules.DoesNotExist:
            return Response(
                {"error": "Object not found."}, status=status.HTTP_404_NOT_FOUND
            )
        serializer = LdrModulesSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ModulesApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self, dump_id):
        try:
            return Modules.objects.get(evidence_id=dump_id)
        except Modules.DoesNotExist:
            return None
        
    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested modules data
        """
        data = self.get_object(dump_id)
        serializer = ModulesSerializer(data)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, dump_id, artifact_id, tag, *args, **kwargs):
        try:
            instance = Modules.objects.get(evidence_id=dump_id, pk=artifact_id)
        except Modules.DoesNotExist:
            return Response(
                {"error": "Object not found."}, status=status.HTTP_404_NOT_FOUND
            )
        serializer = ModulesSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class SSDTApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self, dump_id):
        try:
            return SSDT.objects.get(evidence_id=dump_id)
        except SSDT.DoesNotExist:
            return None
        
    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested SSDT data
        """
        data = self.get_object(dump_id)
        serializer = SSDTSerializer(data)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, dump_id, artifact_id, tag, *args, **kwargs):
        try:
            instance = SSDT.objects.get(evidence_id=dump_id, pk=artifact_id)
        except SSDT.DoesNotExist:
            return Response(
                {"error": "Object not found."}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = SSDTSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class FileScanApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self, dump_id):
        try:
            return FileScan.objects.get(evidence_id=dump_id)
        except FileScan.DoesNotExist:
            return None

    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested FileScan data
        """
        data = self.get_object(dump_id)
        serializer = FileScanSerializer(data)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, dump_id, artifact_id, tag, *args, **kwargs):
        try:
            instance = FileScan.objects.get(evidence_id=dump_id, pk=artifact_id)
        except FileScan.DoesNotExist:
            return Response(
                {"error": "Object not found."}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = FileScanSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class HandlesApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get_object(self, dump_id, pid):
        try:
            return Handles.objects.get(evidence_id=dump_id, PID=pid)
        except Handles.DoesNotExist:
            return None
        
    def get(self, request, dump_id, pid, *args, **kwargs):
        instance = self.get_object(dump_id, pid)
        if instance:
            filtered_data = [d for d in instance.artefacts if d['PID'] == pid]
            if len(filtered_data) > 0:
                return Response(filtered_data, status=status.HTTP_200_OK)
        else:
            compute_handles.delay(evidence_id=dump_id, pid=pid)
            return Response({},status=status.HTTP_201_CREATED)

    def patch(self, request, dump_id, artifact_id, tag, *args, **kwargs):
        try:
            instance = Handles.objects.get(evidence_id=dump_id, pk=artifact_id)
        except Handles.DoesNotExist:
            return Response(
                {"error": "Object not found."}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = HandlesSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PsListDumpApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, _request, dump_id, pid, *args, **kwargs):
        """
        Dump the requested process using the pslist plugin
        """
        dump_process_pslist.delay(evidence_id=dump_id, pid=pid)
        return Response({}, status=status.HTTP_201_CREATED)

class FileScanDumpApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, _request, dump_id, file_id, *args, **kwargs):
        """
        Dump the requested process using the pslist plugin
        """
        dump_file.delay(evidence_id=dump_id, file_id=file_id)
        return Response({}, status=status.HTTP_201_CREATED)

class MemmapDumpApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, _request, dump_id, pid, *args, **kwargs):
        """
        Dump the requested process using the pslist plugin
        """
        dump_process_memmap.delay(evidence_id=dump_id, pid=pid)
        return Response({}, status=status.HTTP_201_CREATED)

class TasksApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        """
        Give the requested tasks if existing.
        """
        tasks = TaskResult.objects.all()
        serializer = TasksSerializer(tasks, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class LootApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, dump_id, *args, **kwargs):
        """
        Get all the loot items
        """
        tasks = Loot.objects.filter(evidence_id=dump_id)
        serializer = LootSerializer(tasks, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)