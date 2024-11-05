from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import VolatilityPlugin
from evidences.models import Evidence
from .serializers import (
    VolatilityPluginDetailSerializer,
    VolatilityPluginNameSerializer,
)
from .tasks import dump_windows_file, dump_windows_process, start_timeliner, dump_windows_handles
from dateutil.parser import parse as parse_date


class EvidencePluginsView(APIView):
    def get(self, request, evidence_id):
        try:
            evidence = Evidence.objects.get(id=evidence_id)
            plugins = VolatilityPlugin.objects.filter(evidence=evidence)
            serializer = VolatilityPluginNameSerializer(plugins, many=True)

            return Response(serializer.data, status=status.HTTP_200_OK)

        except Evidence.DoesNotExist:
            return Response(
                {"error": "Evidence not found"}, status=status.HTTP_404_NOT_FOUND
            )


class TimelinerArtefactsView(APIView):
    def get(self, request, evidence_id, plugin_name):
        try:
            evidence = Evidence.objects.get(id=evidence_id)
            plugin = VolatilityPlugin.objects.get(evidence=evidence, name=plugin_name)
            serializer = VolatilityPluginDetailSerializer(plugin)

            return Response(serializer.data, status=status.HTTP_200_OK)

        except Evidence.DoesNotExist:
            return Response(
                {"error": "Evidence not found"}, status=status.HTTP_404_NOT_FOUND
            )
        except VolatilityPlugin.DoesNotExist:
            return Response(
                {"error": "Plugin not found"}, status=status.HTTP_404_NOT_FOUND
            )


class PluginArtefactsView(APIView):
    def get(self, request, evidence_id, plugin_name):
        try:
            evidence = Evidence.objects.get(id=evidence_id)
            plugin = VolatilityPlugin.objects.get(evidence=evidence, name=plugin_name)
            artefacts = plugin.artefacts or []

            # Get start and end timestamps from query parameters
            start_timestamp = request.query_params.get("start")
            end_timestamp = request.query_params.get("end")

            # Parse and filter artefacts by the created date range
            if start_timestamp and end_timestamp:
                start_date = parse_date(start_timestamp)
                end_date = parse_date(end_timestamp)

                filtered_artefacts = [
                    artefact
                    for artefact in artefacts
                    if artefact.get("Created Date")
                    and start_date <= parse_date(artefact["Created Date"]) <= end_date
                ]
            else:
                filtered_artefacts = artefacts

            serializer = VolatilityPluginDetailSerializer(
                {"name": plugin.name, "artefacts": filtered_artefacts}
            )

            return Response(serializer.data, status=status.HTTP_200_OK)

        except Evidence.DoesNotExist:
            return Response(
                {"error": "Evidence not found"}, status=status.HTTP_404_NOT_FOUND
            )
        except VolatilityPlugin.DoesNotExist:
            return Response(
                {"error": "Plugin not found"}, status=status.HTTP_404_NOT_FOUND
            )
        except ValueError as e:
            # Handle parsing errors from dates
            return Response(
                {"error": f"Invalid date format: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST,
            )


class TimelinerTask(APIView):
    def post(self, request):
        try:
            evidence_id = request.data.get("id")
            evidence = Evidence.objects.get(id=evidence_id)
            start_timeliner.apply_async(args=[evidence.id])
            return Response(status=status.HTTP_200_OK)
        except Evidence.DoesNotExist:
            return Response(
                {"error": "Evidence not found"}, status=status.HTTP_404_NOT_FOUND
            )


class HandlesTask(APIView):
    def post(self, request):
        try:
            evidence_id = request.data.get("evidenceId")
            pid = request.data.get("pid")
            evidence = Evidence.objects.get(id=evidence_id)
            dump_windows_handles.apply_async(args=[evidence.id, pid])
            return Response(status=status.HTTP_200_OK)
        except Evidence.DoesNotExist:
            return Response(
                {"error": "Evidence not found"}, status=status.HTTP_404_NOT_FOUND
            )

class ProcessDumpTask(APIView):
    def post(self, request):
        try:
            evidence_id = request.data.get("evidenceId")
            pid = request.data.get("pid")
            evidence = Evidence.objects.get(id=evidence_id)
            dump_windows_process.apply_async(args=[evidence.id, pid])
            return Response(status=status.HTTP_200_OK)
        except Evidence.DoesNotExist:
            return Response(
                {"error": "Evidence not found"}, status=status.HTTP_404_NOT_FOUND
            )

class FileDumpTask(APIView):
    def post(self, request):
        try:
            evidence_id = request.data.get("evidenceId")
            offset = request.data.get("offset")
            evidence = Evidence.objects.get(id=evidence_id)
            dump_windows_file.apply_async(args=[evidence.id, offset])
            return Response(status=status.HTTP_200_OK)
        except Evidence.DoesNotExist:
            return Response(
                {"error": "Evidence not found"}, status=status.HTTP_404_NOT_FOUND
            )
