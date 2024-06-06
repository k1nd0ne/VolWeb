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
        Return the requested PSTree data.
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
        Return the requested MFTScan.
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
        Return the requested MBRScan data.
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
        Return the requested ADS.
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
        Return the requested TimelineChart.
        """
        data = self.get_object(dump_id)
        serializer = TimelineChartSerializer(data)
        return Response(serializer.data, status=status.HTTP_200_OK)


def build_search_query(field, condition, value1, value2):
    condition_mapping = {
        "=": lambda x: x == value1,
        "!=": lambda x: x != value1,
        "starts": lambda x: x.startswith(value1),
        "ends": lambda x: x.endswith(value1),
        ">": lambda x: x > value1,
        "<": lambda x: x < value1,
        "contains": lambda x: value1 in x,
        "!contains": lambda x: value1 not in x,
        "!ends": lambda x: not x.endswith(value1),
        "!starts": lambda x: not x.startswith(value1),
        "null": lambda x: x is None,
        "!null": lambda x: x is not None,
    }
    if condition == "between" or condition == "!between":
        if condition == "between":
            return lambda x: value1 <= x <= value2
        else:
            return lambda x: not (value1 <= x <= value2)
    if condition in condition_mapping:
        return condition_mapping[condition]
    else:
        return None


def get_fields_maps(field):
    if field == "Plugin":
        return "Plugin"
    if field == "Description":
        return "Description"
    if field == "Changed Date":
        return "Changed Date"
    if field == "Created Date":
        return "Created Date"
    if field == "Accessed Date":
        return "Accessed Date"
    if field == "Modified Date":
        return "Modified Date"
    return None



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
        search_value = request.GET.get("search[value]", "")
        timestamp_min = request.query_params.get("timestamp_min", None)
        timestamp_max = request.query_params.get("timestamp_max", None)

        timeliner_qset = data.artefacts
        search_criterias = request.GET.dict()
        queries = []

        if search_criterias.get("searchBuilder[logic]", None):
            logic = search_criterias["searchBuilder[logic]"]
            for n in range(0, 10):
                condition = search_criterias.get(
                    f"searchBuilder[criteria][{n}][condition]", None
                )
                if condition:
                    if "null" not in condition:
                        value1 = search_criterias[
                            f"searchBuilder[criteria][{n}][value1]"
                        ]
                    else:
                        value1 = None
                    if condition == "between" or condition == "!between":
                        value2 = search_criterias[
                            f"searchBuilder[criteria][{n}][value2]"
                        ]
                    else:
                        value2 = None
                    field = search_criterias[f"searchBuilder[criteria][{n}][data]"]
                    field = get_fields_maps(field)
                    if field and value1 is not None:
                        queries.append(
                            (field, build_search_query(field, condition, value1, value2))
                        )
            if queries:
                if logic == "OR":
                    timeliner_qset = [
                        item
                        for item in timeliner_qset
                        if any(query(item[field]) for field, query in queries)
                    ]
                else:
                    timeliner_qset = [
                        item
                        for item in timeliner_qset
                        if all(query(item[field]) for field, query in queries)
                    ]
        total_records = len(timeliner_qset)

        if search_value:
            timeliner_qset = [
                item
                for item in timeliner_qset
                if search_value.lower() in item["Plugin"].lower()
                or search_value.lower() in item["Description"].lower()
                or search_value.lower() in item["Changed Date"].lower()
                or search_value.lower() in item["Created Date"].lower()
                or search_value.lower() in item["Accessed Date"].lower()
                or search_value.lower() in item["Modified Date"].lower()
            ]

        columns_map = [
            "Plugin",
            "Description",
            "Changed Date",
            "Created Date",
            "Accessed Date",
            "Modified Date",
        ]
        order_column_index = request.GET.get(
            "order[0][column]", ""
        )  # Index of the column to sort
        order_dir = request.GET.get("order[0][dir]", "")  # Sorting direction

        try:
            order_column = columns_map[int(order_column_index)]
        except (IndexError, ValueError):
            order_column = None  # Fallback column or default sorting

        if order_column:
            # Applying sorting
            timeliner_qset.sort(
                key=lambda x: x[order_column],
                reverse=True if order_dir == "desc" else False,
            )

        filtered_data = []

        if timestamp_min and timestamp_max:
            for artefact in timeliner_qset:
                created_date = artefact.get("Created Date")
                if created_date and timestamp_min <= created_date <= timestamp_max:
                    filtered_data.append(artefact)
        else:
            filtered_data = timeliner_qset

        paginator = Paginator(filtered_data, length)
        page_data = paginator.get_page((start // length) + 1)

        total_records_filtered = len(timeliner_qset)
        response = {
            "draw": draw,
            "recordsTotal": total_records,
            "recordsFiltered": total_records_filtered,
            "data": page_data.object_list,
        }

        return Response(response, status=status.HTTP_200_OK)


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
        Return the requested cmdline from the given pid.
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
        Return the requested sids from the given pid.
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
        Return the requested Privileges from the given pid.
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
        Return the requested envars from the pid.
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
        Return the requested psscan data.
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
        Return the requested dlllist from the pid.
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
        Return the requested session from the pid.
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
        Return the requested netstat data
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
        Return the requested netscan data
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
        Return the requested netgraph data
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
        Return the requested Hive data
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
        Return the requested services data
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
        Return the requested Hashdump data
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
        Return the requested Cachedump data
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
        Return the requested Lsadump data
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
        Return the requested malfind data
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
        Return the requested ldrmodules data
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
        Return the requested modules data
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
        Return the requested SSDT data
        """
        data = self.get_object(dump_id)
        serializer = SSDTSerializer(data)
        return Response(serializer.data, status=status.HTTP_200_OK)

class DriverIrpApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get_object(self, dump_id):
        try:
            return DriverIrp.objects.get(evidence_id=dump_id)
        except DriverIrp.DoesNotExist:
            return None

    def get(self, request, dump_id, *args, **kwargs):
        """
        Return the requested DriverIrp data
        """
        data = self.get_object(dump_id)
        serializer = DriverIrpSerializer(data)
        return Response(serializer.data, status=status.HTTP_200_OK)


class IATApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get_object(self, dump_id):
        try:
            return IAT.objects.get(evidence_id=dump_id)
        except IAT.DoesNotExist:
            return None

    def get(self, request, dump_id, *args, **kwargs):
        """
        Return the requested DriverIrp data
        """
        data = self.get_object(dump_id)
        serializer = IATSerializer(data)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ThrdScanApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get_object(self, dump_id):
        try:
            return ThrdScan.objects.get(evidence_id=dump_id)
        except ThrdScan.DoesNotExist:
            return None

    def get(self, request, dump_id, *args, **kwargs):
        """
        Return the requested thrdscan data.
        """
        data = self.get_object(dump_id)
        if data.artefacts:
            return Response(data.artefacts, status=status.HTTP_200_OK)
        else:
            return Response({}, status=status.HTTP_404_NOT_FOUND)

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
        Return the requested FileScan data
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
        """
        Try to compute the handles for the requested process and returns the results.
        """
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
        """
        Try to dump a file using the Filescan plugin
        """
        dump_file.delay(evidence_id=dump_id, offset=offset)
        return Response({}, status=status.HTTP_201_CREATED)


class MemmapDumpApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get(self, _request, dump_id, pid, *args, **kwargs):
        """
        Try to dump a process using the Memmap plugin
        """
        dump_process_memmap.delay(evidence_id=dump_id, pid=pid)
        return Response({}, status=status.HTTP_201_CREATED)


class TasksApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get(self, request, *args, **kwargs):
        """
        Return the requested tasks if existing.
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
