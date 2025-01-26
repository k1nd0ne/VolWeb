from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import VolatilityPlugin, EnrichedProcess
from evidences.models import Evidence
from .serializers import (
    VolatilityPluginDetailSerializer,
    VolatilityPluginNameSerializer,
    EnrichedProcessSerializer,
    TasksSerializer,
)
from rest_framework.permissions import IsAuthenticated
from .tasks import (
    dump_file,
    dump_process,
    start_timeliner,
    dump_windows_handles,
    dump_maps,
    start_extraction,

)
from dateutil.parser import parse as parse_date
from django_celery_results.models import TaskResult
from django.db.models import Q
import ast


class EvidencePluginsView(APIView):
    permission_classes = (IsAuthenticated,)

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


class EnrichedProcessView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, evidence_id, pid):
        try:
            evidence = Evidence.objects.get(id=evidence_id)
            enriched = EnrichedProcess.objects.get(evidence=evidence, pid=pid)
            serializer = EnrichedProcessSerializer(enriched, many=False)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Evidence.DoesNotExist:
            return Response(
                {"error": "Evidence not found"}, status=status.HTTP_404_NOT_FOUND
            )

        except EnrichedProcess.DoesNotExist:
            return Response(
                {"error": "Enriched process not found"},
                status=status.HTTP_404_NOT_FOUND,
            )


class TimelinerArtefactsView(APIView):
    permission_classes = (IsAuthenticated,)

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
    permission_classes = (IsAuthenticated,)

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

class RestartAnalysisTask(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            evidence_id = request.data.get("id")
            evidence = Evidence.objects.get(id=evidence_id)
            start_extraction.apply_async(args=[evidence.id])
            return Response(status=status.HTTP_200_OK)
        except Evidence.DoesNotExist:
            return Response(
                {"error": "Evidence not found"}, status=status.HTTP_404_NOT_FOUND
            )


class TimelinerTask(APIView):
    permission_classes = (IsAuthenticated,)

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
    permission_classes = (IsAuthenticated,)

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


class ProcessDumpPslistTask(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            evidence_id = request.data.get("evidenceId")
            pid = request.data.get("pid")
            evidence = Evidence.objects.get(id=evidence_id)
            dump_process.apply_async(args=[evidence.id, pid])
            return Response(status=status.HTTP_200_OK)
        except Evidence.DoesNotExist:
            return Response(
                {"error": "Evidence not found"}, status=status.HTTP_404_NOT_FOUND
            )


class ProcessDumpMapsTask(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            evidence_id = request.data.get("evidenceId")
            pid = request.data.get("pid")
            evidence = Evidence.objects.get(id=evidence_id)
            dump_maps.apply_async(args=[evidence.id, pid])
            return Response(status=status.HTTP_200_OK)
        except Evidence.DoesNotExist:
            return Response(
                {"error": "Evidence not found"}, status=status.HTTP_404_NOT_FOUND
            )


class FileDumpTask(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            evidence_id = request.data.get("evidenceId")
            offset = request.data.get("offset")
            evidence = Evidence.objects.get(id=evidence_id)
            dump_file.apply_async(args=[evidence.id, offset])
            return Response(status=status.HTTP_200_OK)
        except Evidence.DoesNotExist:
            return Response(
                {"error": "Evidence not found"}, status=status.HTTP_404_NOT_FOUND
            )


class TasksApiView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, evidence_id, *args, **kwargs):
        """
        Return the requested tasks if existing.
        """
        tasks = TaskResult.objects.filter(Q(status="STARTED") | Q(status="PENDING"))
        try:
            if tasks:
                filtered_tasks = [
                    task
                    for task in tasks
                    if ast.literal_eval(ast.literal_eval(task.task_args))[0]
                    == evidence_id
                ]
                serializer = TasksSerializer(filtered_tasks, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)
        except:
            return Response(status=status.HTTP_404_NOT_FOUND)
        else:
            return Response(status=status.HTTP_404_NOT_FOUND)
