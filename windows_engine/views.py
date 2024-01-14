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

    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested PSTree.
        """
        tree = PsTree.objects.filter(evidence_id=dump_id)
        serializer = PsTreeSerializer(tree, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class TimelineChartApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested Timeline.
        """
        timeline = TimeLineChart.objects.filter(evidence_id=dump_id)
        serializer = TimelineChartSerializer(timeline, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class TimelineDataApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, dump_id, timestamp, *args, **kwargs):
        """
        Give the requested Timeline Date from the timestamp.
        """
        data = Timeliner.objects.filter(evidence_id=dump_id, CreatedDate=timestamp)
        serializer = TimelineDataSerializer(data, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

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

    def get(self, request, dump_id, pid, *args, **kwargs):
        """
        Give the requested cmdline from the pid.
        """
        data = CmdLine.objects.filter(evidence_id=dump_id, PID=pid)
        serializer = CmdLineSerializer(data, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class GetSIDsApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, dump_id, pid, *args, **kwargs):
        """
        Give the requested cmdline from the pid.
        """
        data = GetSIDs.objects.filter(evidence_id=dump_id, PID=pid)
        serializer = GetSIDsSerializer(data, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

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

    def get(self, request, dump_id, pid, *args, **kwargs):
        """
        Give the requested cmdline from the pid.
        """
        data = Privs.objects.filter(evidence_id=dump_id, PID=pid)
        serializer = PrivsSerializer(data, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

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

    def get(self, request, dump_id, pid, *args, **kwargs):
        """
        Give the requested cmdline from the pid.
        """
        data = Envars.objects.filter(evidence_id=dump_id, PID=pid)
        serializer = EnvarsSerializer(data, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

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

    def get(self, request, dump_id, pid, *args, **kwargs):
        """
        Give the requested cmdline from the pid.
        """
        data = DllList.objects.filter(evidence_id=dump_id, PID=pid)
        serializer = DllListSerializer(data, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

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

    def get(self, request, dump_id, pid, *args, **kwargs):
        """
        Give the requested cmdline from the pid.
        """
        data = Sessions.objects.filter(evidence_id=dump_id, ProcessID=pid)
        serializer = SessionsSerializer(data, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

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

    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested netstat data
        """
        data = NetStat.objects.filter(evidence_id=dump_id)
        serializer = NetStatSerializer(data, many=True)
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

    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested netscan data
        """
        data = NetScan.objects.filter(evidence_id=dump_id)
        serializer = NetScanSerializer(data, many=True)
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

    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested modules data
        """
        data = SvcScan.objects.filter(evidence_id=dump_id)
        serializer = SvcScanSerializer(data, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class HashdumpApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested Hashdump data
        """
        data = Hashdump.objects.filter(evidence_id=dump_id)
        serializer = HashdumpSerializer(data, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class CachedumpApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested Cachedump data
        """
        data = Cachedump.objects.filter(evidence_id=dump_id)
        serializer = CachedumpSerializer(data, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class LsadumpApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested Lsadump data
        """
        data = Lsadump.objects.filter(evidence_id=dump_id)
        serializer = LsadumpSerializer(data, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class MalfindApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested malfind data
        """
        data = Malfind.objects.filter(evidence_id=dump_id)
        serializer = MalfindSerializer(data, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class LdrModulesApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested ldrmodules data
        """
        data = LdrModules.objects.filter(evidence_id=dump_id)
        serializer = LdrModulesSerializer(data, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class ModulesApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested modules data
        """
        data = Modules.objects.filter(evidence_id=dump_id)
        serializer = ModulesSerializer(data, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class SSDTApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested SSDT data
        """
        data = SSDT.objects.filter(evidence_id=dump_id)
        serializer = SSDTSerializer(data, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class FileScanApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested FileScan data
        """
        data = FileScan.objects.filter(evidence_id=dump_id)
        serializer = FileScanSerializer(data, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class HandlesApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, dump_id, pid, *args, **kwargs):
        """
        Give the requested handles if existing.
        """
        data = Handles.objects.filter(evidence_id=dump_id, PID=pid)
        serializer = HandlesSerializer(data, many=True)
        if len(data) > 0:
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            compute_handles.delay(evidence_id=dump_id, pid=pid)
            return Response(serializer.data, status=status.HTTP_201_CREATED)

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