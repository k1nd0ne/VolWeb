from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from main.forms import IndicatorForm
from rest_framework.authentication import SessionAuthentication, TokenAuthentication

from windows_engine.tasks import (
    compute_handles,
    dump_process_pslist,
    dump_process_memmap,
    dump_file,
)
from windows_engine.models import *
from evidences.models import Evidence
from django_celery_results.models import TaskResult
from windows_engine.serializers import *
from rest_framework.views import APIView
from rest_framework import permissions
from rest_framework import status
from rest_framework.response import Response
from django.core.paginator import Paginator
from django.db.models import Q


@login_required
def review(request, dump_id):
    evidence = Evidence.objects.get(dump_id=dump_id)
    stix_indicator = IndicatorForm()
    return render(
        request,
        "windows_engine/review_evidence.html",
        {"evidence": evidence, "stix_indicator_form": stix_indicator},
    )


class PsTreeApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

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


class MFTScanApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get_object(self, dump_id):
        try:
            return MFTScan.objects.get(evidence_id=dump_id)
        except MFTScan.DoesNotExist:
            return None

    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested MFTScan.
        """
        data = self.get_object(dump_id)
        serializer = MFTScanSerializer(data)
        return Response(serializer.data, status=status.HTTP_200_OK)


class MBRScanApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get_object(self, dump_id):
        try:
            return MBRScan.objects.get(evidence_id=dump_id)
        except MBRScan.DoesNotExist:
            return None

    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested MBRScan data.
        """
        data = self.get_object(dump_id)
        serializer = MBRScanSerializer(data)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ADSApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get_object(self, dump_id):
        try:
            return ADS.objects.get(evidence_id=dump_id)
        except ADS.DoesNotExist:
            return None

    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested ADS.
        """
        data = self.get_object(dump_id)
        serializer = ADSSerializer(data)
        return Response(serializer.data, status=status.HTTP_200_OK)


class TimelineChartApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

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
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get_object(self, dump_id):
        try:
            return Timeliner.objects.get(evidence_id=dump_id)
        except Timeliner.DoesNotExist:
            return None

    def get(self, request, dump_id, *args, **kwargs):
        """
        Serve the requested timeline data with server-side processing.
        """
        data = self.get_object(dump_id)
        if not data:
            return Response({}, status=status.HTTP_404_NOT_FOUND)
        draw = int(request.query_params.get("draw", 0))
        start = int(request.query_params.get("start", 0))
        length = int(request.query_params.get("length", 25))
        timestamp_min = request.query_params.get("timestamp_min", None)
        timestamp_max = request.query_params.get("timestamp_max", None)

        filtered_data = []
        if timestamp_min and timestamp_max:
            for artefact in data.artefacts:
                created_date = artefact.get("Created Date")
                if created_date and timestamp_min <= created_date <= timestamp_max:
                    filtered_data.append(artefact)
        else:
            filtered_data = data.artefacts

        paginator = Paginator(filtered_data, length)
        page_data = paginator.get_page((start // length) + 1)

        return Response(
            {
                "draw": draw,
                "recordsTotal": paginator.count,
                "recordsFiltered": paginator.count,  # Adjust this value if you implement search
                "data": page_data.object_list,
            },
            status=status.HTTP_200_OK,
        )


class CmdLineApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

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
        if data.artefacts:
            filtered_data = [d for d in data.artefacts if d["PID"] == pid]
            return Response(filtered_data, status=status.HTTP_200_OK)
        else:
            return Response({}, status=status.HTTP_404_NOT_FOUND)


class GetSIDsApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

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
        if data.artefacts:
            filtered_data = [d for d in data.artefacts if d["PID"] == pid]
            return Response(filtered_data, status=status.HTTP_200_OK)
        else:
            return Response({}, status=status.HTTP_404_NOT_FOUND)


class PrivsApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

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
        if data.artefacts:
            filtered_data = [d for d in data.artefacts if d["PID"] == pid]
            return Response(filtered_data, status=status.HTTP_200_OK)
        else:
            return Response({}, status=status.HTTP_404_NOT_FOUND)


class EnvarsApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get_object(self, dump_id):
        try:
            return Envars.objects.get(evidence_id=dump_id)
        except Envars.DoesNotExist:
            return None

    def get(self, request, dump_id, pid, *args, **kwargs):
        """
        Give the requested envars from the pid.
        """
        data = self.get_object(dump_id)
        if data.artefacts:
            filtered_data = [d for d in data.artefacts if d["PID"] == pid]
            return Response(filtered_data, status=status.HTTP_200_OK)
        else:
            return Response({}, status=status.HTTP_404_NOT_FOUND)


class PsScanApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get_object(self, dump_id):
        try:
            return PsScan.objects.get(evidence_id=dump_id)
        except PsScan.DoesNotExist:
            return None

    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested psscan data.
        """
        data = self.get_object(dump_id)
        if data.artefacts:
            return Response(data.artefacts, status=status.HTTP_200_OK)
        else:
            return Response({}, status=status.HTTP_404_NOT_FOUND)


class DllListApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get_object(self, dump_id):
        try:
            return DllList.objects.get(evidence_id=dump_id)
        except DllList.DoesNotExist:
            return None

    def get(self, request, dump_id, pid, *args, **kwargs):
        """
        Give the requested dlllist from the pid.
        """
        data = self.get_object(dump_id)
        if data.artefacts:
            filtered_data = [d for d in data.artefacts if d["PID"] == pid]
            return Response(filtered_data, status=status.HTTP_200_OK)
        else:
            return Response({}, status=status.HTTP_404_NOT_FOUND)


class SessionsApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

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
        if data.artefacts:
            filtered_data = [d for d in data.artefacts if d["Process ID"] == pid]
            return Response(filtered_data, status=status.HTTP_200_OK)
        else:
            return Response({}, status=status.HTTP_404_NOT_FOUND)


class NetStatApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

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


class NetScanApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

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


class NetGraphApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get_object(self, dump_id):
        try:
            return NetGraph.objects.get(evidence_id=dump_id)
        except NetGraph.DoesNotExist:
            return None

    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested netgraph data
        """
        data = self.get_object(dump_id)
        serializer = NetGraphSerializer(data)
        return Response(serializer.data, status=status.HTTP_200_OK)


class HiveListApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get_object(self, dump_id):
        try:
            return HiveList.objects.get(evidence_id=dump_id)
        except HiveList.DoesNotExist:
            return None

    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested services data
        """
        data = self.get_object(dump_id)
        serializer = HiveListSerializer(data)
        return Response(serializer.data, status=status.HTTP_200_OK)


class SvcScanApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

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


class HashdumpApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

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
    authentication_classes = [SessionAuthentication, TokenAuthentication]

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
    authentication_classes = [SessionAuthentication, TokenAuthentication]

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
    authentication_classes = [SessionAuthentication, TokenAuthentication]

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
    authentication_classes = [SessionAuthentication, TokenAuthentication]

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


class ModulesApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

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


class SSDTApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

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


class FileScanApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

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


class HandlesApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get_object(self, dump_id, pid):
        try:
            return Handles.objects.get(evidence_id=dump_id, PID=pid)
        except Handles.DoesNotExist:
            return None

    def get(self, request, dump_id, pid, *args, **kwargs):
        instance = self.get_object(dump_id, pid)
        if instance:
            filtered_data = [d for d in instance.artefacts if d["PID"] == pid]
            return Response(filtered_data, status=status.HTTP_200_OK)

        else:
            compute_handles.apply_async(
                args=[dump_id, pid],
                priority=1,
            )
            return Response({}, status=status.HTTP_201_CREATED)


class PsListDumpApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get(self, _request, dump_id, pid, *args, **kwargs):
        """
        Dump the requested process using the pslist plugin
        """
        dump_process_pslist.apply_async(
            args=[dump_id, pid],
            priority=1,
        )
        return Response({}, status=status.HTTP_201_CREATED)


class FileScanDumpApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get(self, _request, dump_id, offset, *args, **kwargs):
        dump_file.delay(evidence_id=dump_id, offset=offset)
        return Response({}, status=status.HTTP_201_CREATED)


class MemmapDumpApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get(self, _request, dump_id, pid, *args, **kwargs):
        """
        Dump the requested process using the pslist plugin
        """
        dump_process_memmap.delay(evidence_id=dump_id, pid=pid)
        return Response({}, status=status.HTTP_201_CREATED)


class TasksApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get(self, request, *args, **kwargs):
        """
        Give the requested tasks if existing.
        """
        tasks = TaskResult.objects.filter(Q(status="STARTED") | Q(status="PENDING"))
        serializer = TasksSerializer(tasks, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class LootApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get(self, request, dump_id, *args, **kwargs):
        """
        Get all the loot items
        """
        tasks = Loot.objects.filter(evidence_id=dump_id)
        serializer = LootSerializer(tasks, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
