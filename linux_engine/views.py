from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from linux_engine.models import *
from evidences.models import Evidence
from linux_engine.serializers import *
from rest_framework.views import APIView
from rest_framework import permissions
from rest_framework import status
from rest_framework.response import Response
from django.core.paginator import Paginator
from django.db.models import Q
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from main.forms import IndicatorForm


@login_required
def review(request, dump_id):
    evidence = Evidence.objects.get(dump_id=dump_id)
    stix_indicator = IndicatorForm()
    return render(
        request,
        "linux_engine/review_evidence.html",
        {"evidence": evidence, "stix_indicator_form": stix_indicator},
    )


class PsTreeApiView(APIView):
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


class PsAuxApiView(APIView):
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get_object(self, dump_id):
        try:
            return PsAux.objects.get(evidence_id=dump_id)
        except PsAux.DoesNotExist:
            return None

    def get(self, request, dump_id, pid, *args, **kwargs):
        """
        Give the requested psaux from the pid.
        """
        data = self.get_object(dump_id)
        if data.artefacts:
            filtered_data = [d for d in data.artefacts if d["PID"] == pid]
            return Response(filtered_data, status=status.HTTP_200_OK)
        else:
            return Response({}, status=status.HTTP_404_NOT_FOUND)


class LsofApiView(APIView):
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get_object(self, dump_id):
        try:
            return Lsof.objects.get(evidence_id=dump_id)
        except Lsof.DoesNotExist:
            return None

    def get(self, request, dump_id, pid, *args, **kwargs):
        """
        Give the requested psaux from the pid.
        """
        data = self.get_object(dump_id)
        if data.artefacts:
            filtered_data = [d for d in data.artefacts if d["PID"] == pid]
            return Response(filtered_data, status=status.HTTP_200_OK)
        else:
            return Response({}, status=status.HTTP_404_NOT_FOUND)


class ElfsApiView(APIView):
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get_object(self, dump_id):
        try:
            return Elfs.objects.get(evidence_id=dump_id)
        except Elfs.DoesNotExist:
            return None

    def get(self, request, dump_id, pid, *args, **kwargs):
        """
        Give the requested psaux from the pid.
        """
        data = self.get_object(dump_id)
        if data.artefacts:
            filtered_data = [d for d in data.artefacts if d["PID"] == pid]
            return Response(filtered_data, status=status.HTTP_200_OK)
        else:
            return Response({}, status=status.HTTP_404_NOT_FOUND)


class EnvarsApiView(APIView):
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get_object(self, dump_id):
        try:
            return Envars.objects.get(evidence_id=dump_id)
        except Envars.DoesNotExist:
            return None

    def get(self, request, dump_id, pid, *args, **kwargs):
        """
        Give the requested psaux from the pid.
        """
        data = self.get_object(dump_id)
        if data.artefacts:
            filtered_data = [d for d in data.artefacts if d["PID"] == pid]
            return Response(filtered_data, status=status.HTTP_200_OK)
        else:
            return Response({}, status=status.HTTP_404_NOT_FOUND)


class CapabilitiesApiView(APIView):
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get_object(self, dump_id):
        try:
            return Capabilities.objects.get(evidence_id=dump_id)
        except Capabilities.DoesNotExist:
            return None

    def get(self, request, dump_id, pid, *args, **kwargs):
        """
        Give the requested psaux from the pid.
        """
        data = self.get_object(dump_id)
        if data.artefacts:
            filtered_data = [d for d in data.artefacts if d["Pid"] == pid]
            return Response(filtered_data, status=status.HTTP_200_OK)
        else:
            return Response({}, status=status.HTTP_404_NOT_FOUND)


class PsScanApiView(APIView):
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


class tty_checkApiView(APIView):
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get_object(self, dump_id):
        try:
            return tty_check.objects.get(evidence_id=dump_id)
        except tty_check.DoesNotExist:
            return None

    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested mount_info data.
        """
        data = self.get_object(dump_id)
        if data.artefacts:
            return Response(data.artefacts, status=status.HTTP_200_OK)
        else:
            return Response({}, status=status.HTTP_404_NOT_FOUND)


class MountInfoApiView(APIView):
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get_object(self, dump_id):
        try:
            return MountInfo.objects.get(evidence_id=dump_id)
        except MountInfo.DoesNotExist:
            return None

    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested mount_info data.
        """
        data = self.get_object(dump_id)
        if data.artefacts:
            return Response(data.artefacts, status=status.HTTP_200_OK)
        else:
            return Response({}, status=status.HTTP_404_NOT_FOUND)


class KmsgApiView(APIView):
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get_object(self, dump_id):
        try:
            return Kmsg.objects.get(evidence_id=dump_id)
        except Kmsg.DoesNotExist:
            return None

    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested kmsg data.
        """
        data = self.get_object(dump_id)
        if data.artefacts:
            return Response(data.artefacts, status=status.HTTP_200_OK)
        else:
            return Response({}, status=status.HTTP_404_NOT_FOUND)


class MalfindApiView(APIView):
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


class LsmodApiView(APIView):
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get_object(self, dump_id):
        try:
            return Lsmod.objects.get(evidence_id=dump_id)
        except Lsmod.DoesNotExist:
            return None

    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested kernel modules
        """
        data = self.get_object(dump_id)
        serializer = LsmodSerializer(data)
        return Response(serializer.data, status=status.HTTP_200_OK)


class SockstatApiView(APIView):
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get_object(self, dump_id):
        try:
            return Sockstat.objects.get(evidence_id=dump_id)
        except Sockstat.DoesNotExist:
            return None

    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested sockstat data.
        """
        data = self.get_object(dump_id)
        if data.artefacts:
            return Response(data.artefacts, status=status.HTTP_200_OK)
        else:
            return Response({}, status=status.HTTP_404_NOT_FOUND)


class NetGraphApiView(APIView):
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


class BashApiView(APIView):
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get_object(self, dump_id):
        try:
            return Bash.objects.get(evidence_id=dump_id)
        except Bash.DoesNotExist:
            return None

    def get(self, request, dump_id, *args, **kwargs):
        """
        Give the requested bash data.
        """
        data = self.get_object(dump_id)
        if data.artefacts:
            return Response(data.artefacts, status=status.HTTP_200_OK)
        else:
            return Response({}, status=status.HTTP_404_NOT_FOUND)


class TimelineChartApiView(APIView):
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

        # Server-side parameters
        draw = int(
            request.query_params.get("draw", 0)
        )  # Used by DataTables to ensure that the Ajax returns from server-side processing are drawn in sequence
        start = int(request.query_params.get("start", 0))
        length = int(request.query_params.get("length", 25))
        timestamp_min = request.query_params.get("timestamp_min", None)
        timestamp_max = request.query_params.get("timestamp_max", None)

        # Filtering based on timestamp
        filtered_data = []
        if timestamp_min and timestamp_max:
            for artefact in data.artefacts:
                created_date = artefact.get("Created Date")
                if created_date and timestamp_min <= created_date <= timestamp_max:
                    filtered_data.append(artefact)
        else:
            filtered_data = data.artefacts

        # Implement search and order by functionality if necessary

        # Server-side pagination
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
