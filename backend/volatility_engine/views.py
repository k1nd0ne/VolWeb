from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import VolatilityPlugin, EnrichedProcess
from evidences.models import Evidence
from django.conf import settings
from datetime import datetime, timezone
import os
import json
from yararules.models import YaraRule
from yararulesets.models import YaraRuleSet
from .serializers import (
    VolatilityPluginDetailSerializer,
    VolatilityPluginNameSerializer,
    EnrichedProcessSerializer,
    TasksSerializer,
)
from rest_framework.permissions import IsAuthenticated
from core.permissions import check_evidence_access
from .tasks import (
    dump_file,
    dump_process,
    start_timeliner,
    dump_windows_handles,
    dump_maps,
    start_selective_extraction,
    start_yarascan,
    start_yararule_validation,
    start_ruleset_validation,
)
from dateutil.parser import parse as parse_date
from django_celery_results.models import TaskResult
import ast
import json
from django.db.models import Count, Q


def _get_evidence_or_403(evidence_id, user):
    """
    Fetch Evidence by id and verify the user has access to it.
    Returns (evidence, None) on success or (None, Response) on failure.
    """
    try:
        evidence = Evidence.objects.get(id=evidence_id)
    except Evidence.DoesNotExist:
        return None, Response({"error": "Evidence not found"}, status=status.HTTP_404_NOT_FOUND)
    try:
        check_evidence_access(user, evidence)
    except Exception:
        return None, Response({"error": "You do not have access to this evidence."}, status=status.HTTP_403_FORBIDDEN)
    return evidence, None

class EvidencePluginsView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, evidence_id):
        evidence, err = _get_evidence_or_403(evidence_id, request.user)
        if err:
            return err
        plugins = VolatilityPlugin.objects.filter(evidence=evidence, display="True")
        serializer = VolatilityPluginNameSerializer(plugins, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class EnrichedProcessView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, evidence_id, pid):
        evidence, err = _get_evidence_or_403(evidence_id, request.user)
        if err:
            return err
        try:
            enriched = EnrichedProcess.objects.get(evidence=evidence, pid=pid)
            serializer = EnrichedProcessSerializer(enriched, many=False)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except EnrichedProcess.DoesNotExist:
            return Response(
                {"error": "Enriched process not found"},
                status=status.HTTP_404_NOT_FOUND,
            )


class TimelinerArtefactsView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, evidence_id, plugin_name):
        evidence, err = _get_evidence_or_403(evidence_id, request.user)
        if err:
            return err
        try:
            plugin = VolatilityPlugin.objects.get(evidence=evidence, name=plugin_name)
            serializer = VolatilityPluginDetailSerializer(plugin)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except VolatilityPlugin.DoesNotExist:
            return Response(
                {"error": "Plugin not found"}, status=status.HTTP_404_NOT_FOUND
            )


class PluginArtefactsView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, evidence_id, plugin_name):
        evidence, err = _get_evidence_or_403(evidence_id, request.user)
        if err:
            return err
        try:
            # Special handling for YARA scan results to avoid duplicates
            if plugin_name == "volatility3.plugins.yarascan.latest":
                # Get the most recent one if there are duplicates
                plugin = VolatilityPlugin.objects.filter(
                    evidence=evidence, 
                    name=plugin_name
                ).order_by('-id').first()
                
                if not plugin:
                    return Response(
                        {"error": "Plugin not found"}, 
                        status=status.HTTP_404_NOT_FOUND
                    )
            else:
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


class PauseExtractionTask(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        evidence_id = request.data.get("id")
        evidence, err = _get_evidence_or_403(evidence_id, request.user)
        if err:
            return err
        evidence.extraction_control = "paused"
        evidence.save(update_fields=["extraction_control"])
        return Response(status=status.HTTP_200_OK)


class ResumeExtractionTask(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        evidence_id = request.data.get("id")
        evidence, err = _get_evidence_or_403(evidence_id, request.user)
        if err:
            return err
        evidence.extraction_control = "running"
        evidence.save(update_fields=["extraction_control"])
        return Response(status=status.HTTP_200_OK)


class StopExtractionTask(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        evidence_id = request.data.get("id")
        evidence, err = _get_evidence_or_403(evidence_id, request.user)
        if err:
            return err
        try:

            # Revoke the Celery task to kill it immediately
            if evidence.celery_task_id:
                from backend.celery import app
                app.control.revoke(evidence.celery_task_id, terminate=True, signal="SIGTERM")

            evidence.extraction_control = "idle"
            evidence.celery_task_id = ""
            evidence.status = 100
            evidence.save(update_fields=["extraction_control", "celery_task_id", "status"])
            return Response(status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class TimelinerTask(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        evidence_id = request.data.get("id")
        evidence, err = _get_evidence_or_403(evidence_id, request.user)
        if err:
            return err
        start_timeliner.apply_async(args=[evidence.id])
        return Response(status=status.HTTP_200_OK)


class HandlesTask(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        evidence_id = request.data.get("evidenceId")
        pid = request.data.get("pid")
        evidence, err = _get_evidence_or_403(evidence_id, request.user)
        if err:
            return err
        dump_windows_handles.apply_async(args=[evidence.id, pid])
        return Response(status=status.HTTP_200_OK)


class ProcessDumpPslistTask(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        evidence_id = request.data.get("evidenceId")
        pid = request.data.get("pid")
        evidence, err = _get_evidence_or_403(evidence_id, request.user)
        if err:
            return err
        dump_process.apply_async(args=[evidence.id, pid])
        return Response(status=status.HTTP_200_OK)


class ProcessDumpMapsTask(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        evidence_id = request.data.get("evidenceId")
        pid = request.data.get("pid")
        evidence, err = _get_evidence_or_403(evidence_id, request.user)
        if err:
            return err
        dump_maps.apply_async(args=[evidence.id, pid])
        return Response(status=status.HTTP_200_OK)


class FileDumpTask(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        evidence_id = request.data.get("evidenceId")
        file_offset = request.data.get("offset")
        evidence, err = _get_evidence_or_403(evidence_id, request.user)
        if err:
            return err
        dump_file.apply_async(args=[evidence.id, file_offset])
        return Response(status=status.HTTP_200_OK)


class TasksApiView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, evidence_id, *args, **kwargs):
        """
        Return the requested tasks if existing.
        """
        evidence, err = _get_evidence_or_403(evidence_id, request.user)
        if err:
            return err
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

class RestartRuleCompilationTask(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            yararule_id = request.data.get("id")
            yararule = YaraRule.objects.get(id=yararule_id)
            start_yararule_validation.apply_async(args=[yararule.id])
    
            return Response(status=status.HTTP_200_OK)
        except YaraRule.DoesNotExist:
            return Response(
                {"error": "YaraRule not found"}, status=status.HTTP_404_NOT_FOUND
            )
            
class RestartRulesetCompilationTask(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            yararuleset_id = request.data.get("id")
            yararuleset = YaraRuleSet.objects.get(id=yararuleset_id)
            start_ruleset_validation.apply_async(args=[yararuleset.id])
            return Response(status=status.HTTP_200_OK)
        except Evidence.DoesNotExist:
            return Response(
                {"error": "Evidence not found"}, status=status.HTTP_404_NOT_FOUND
            )
            
class YaraScanTask(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        evidence_id = request.data.get("id")
        if not evidence_id:
            return Response({"error": "Evidence ID is required"}, status=status.HTTP_400_BAD_REQUEST)
        evidence, err = _get_evidence_or_403(evidence_id, request.user)
        if err:
            return err
        # Linux YARA scanning needs the kernel symbols too.
        if evidence.os == "linux":
            from .models import LinuxSymbolResolution
            resolution = LinuxSymbolResolution.objects.filter(evidence=evidence).first()
            if not resolution or resolution.status != "ready":
                return Response(
                    {"error": "Kernel symbols (ISF) are not ready for this Linux evidence. "
                              "Resolve them from the plugin selection screen or upload a matching ISF."},
                    status=status.HTTP_409_CONFLICT,
                )
        try:
            rulesets = request.data.get("rulesets", [])
            rules = request.data.get("rules", [])
            scan_scope = request.data.get("scan_scope", "vad")
            if scan_scope not in ("vad", "kernel"):
                return Response(
                    {"error": "scan_scope must be either 'vad' or 'kernel'"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            task = start_yarascan.apply_async(
                args=[evidence.id],
                kwargs={"rulesets": rulesets, "rules": rules, "scan_scope": scan_scope},
                queue="yarascan",
            )
            evidence.celery_task_id = task.id
            evidence.save(update_fields=["celery_task_id"])
            return Response({"message": "YARA scan task started successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": f"Failed to start YARA scan: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class StopYaraScanTask(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        evidence_id = request.data.get("id")
        evidence, err = _get_evidence_or_403(evidence_id, request.user)
        if err:
            return err
        try:
            if evidence.celery_task_id:
                from backend.celery import app
                from channels.layers import get_channel_layer
                from asgiref.sync import async_to_sync

                app.control.revoke(evidence.celery_task_id, terminate=True, signal="SIGTERM")
                evidence.celery_task_id = ""
                evidence.save(update_fields=["celery_task_id"])

                channel_layer = get_channel_layer()
                async_to_sync(channel_layer.group_send)(
                    f"volatility_tasks_{evidence_id}",
                    {
                        "type": "send_notification",
                        "message": {
                            "name": "yarascan",
                            "status": "stopped",
                            "result": "false",
                        },
                    },
                )

            return Response({"message": "YARA scan stopped"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": f"Failed to stop scan: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class YaraScanHistoryView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, evidence_id):
        """
        Get metadata for the most recent YARA scan (name, description, count).
        Does NOT return artefacts — use /yarascan/results/ for paginated results.
        """
        evidence, err = _get_evidence_or_403(evidence_id, request.user)
        if err:
            return err
        try:
            scan = VolatilityPlugin.objects.filter(
                evidence_id=evidence_id,
                name="volatility3.plugins.yarascan.latest"
            ).order_by('-id').first()

            if not scan:
                return Response([], status=status.HTTP_200_OK)

            artefacts = scan.artefacts or {}
            if isinstance(artefacts, dict) and artefacts.get("streaming"):
                count = artefacts.get("count", 0)
            else:
                count = len(artefacts) if isinstance(artefacts, list) else 0

            return Response([{
                "name": scan.name,
                "description": scan.description,
                "count": count,
            }], status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": f"Failed to fetch scan history: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def delete(self, request, evidence_id):
        """
        Delete all YARA scans for an evidence
        """
        evidence, err = _get_evidence_or_403(evidence_id, request.user)
        if err:
            return err
        try:
            scans = VolatilityPlugin.objects.filter(
                evidence_id=evidence_id,
                name="volatility3.plugins.yarascan.latest"
            )
            # Remove JSONL result files before deleting DB rows
            for scan in scans:
                artefacts = scan.artefacts or {}
                if isinstance(artefacts, dict) and artefacts.get("streaming"):
                    file_path = artefacts.get("file", "")
                    if file_path and os.path.exists(file_path):
                        try:
                            os.unlink(file_path)
                        except Exception:
                            pass

            deleted_count = scans.delete()[0]

            return Response(
                {"message": "Successfully deleted YARA scan" if deleted_count > 0 else "No YARA scan found"},
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {"error": f"Failed to delete scan history: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class YaraScanDetailView(APIView):
    permission_classes = (IsAuthenticated,)

    def delete(self, request, evidence_id, plugin_name):
        """
        Delete a specific YARA scan
        """
        evidence, err = _get_evidence_or_403(evidence_id, request.user)
        if err:
            return err
        try:
            scans = VolatilityPlugin.objects.filter(evidence_id=evidence_id, name=plugin_name)
            # Remove JSONL result files before deleting DB rows
            for scan in scans:
                artefacts = scan.artefacts or {}
                if isinstance(artefacts, dict) and artefacts.get("streaming"):
                    file_path = artefacts.get("file", "")
                    if file_path and os.path.exists(file_path):
                        try:
                            os.unlink(file_path)
                        except Exception:
                            pass
            deleted_count = scans.delete()[0]

            if deleted_count == 0:
                return Response(
                    {"error": "YARA scan not found"},
                    status=status.HTTP_404_NOT_FOUND
                )

            return Response(
                {"message": f"YARA scan deleted successfully (removed {deleted_count} entries)"},
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {"error": f"Failed to delete YARA scan: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class YaraScanResultsView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, evidence_id):
        """
        Return a paginated page of YARA scan results.
        Supports both streaming (JSONL file) and legacy (artefacts list) formats.
        Query params: page (1-based), page_size
        """
        evidence, err = _get_evidence_or_403(evidence_id, request.user)
        if err:
            return err
        try:
            page = max(1, int(request.query_params.get("page", 1)))
            page_size = min(500, max(1, int(request.query_params.get("page_size", 100))))
            offset = (page - 1) * page_size

            scan = VolatilityPlugin.objects.filter(
                evidence_id=evidence_id,
                name="volatility3.plugins.yarascan.latest"
            ).order_by('-id').first()

            if not scan:
                return Response({"error": "No YARA scan found"}, status=status.HTTP_404_NOT_FOUND)

            artefacts = scan.artefacts or {}

            if isinstance(artefacts, dict) and artefacts.get("streaming"):
                file_path = artefacts.get("file", "")
                total_count = artefacts.get("count", 0)

                if not file_path or not os.path.exists(file_path):
                    return Response(
                        {"error": "Scan results file not found. The scan may have been run on a different host or the file was deleted."},
                        status=status.HTTP_404_NOT_FOUND
                    )

                results = []
                with open(file_path, 'r') as f:
                    for i, line in enumerate(f):
                        if i < offset:
                            continue
                        if len(results) >= page_size:
                            break
                        line = line.strip()
                        if line:
                            results.append(json.loads(line))
            else:
                # Legacy scans: artefacts stored as a JSON list in the DB
                artefacts_list = artefacts if isinstance(artefacts, list) else []
                total_count = len(artefacts_list)
                results = artefacts_list[offset:offset + page_size]

            return Response({
                "count": total_count,
                "results": results,
                "page": page,
                "page_size": page_size,
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": f"Failed to fetch scan results: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AvailablePluginsView(APIView):
    """
    Returns the full plugin catalog grouped by category, filtered by the evidence OS.
    """
    permission_classes = (IsAuthenticated,)

    def get(self, request, evidence_id):
        evidence, err = _get_evidence_or_403(evidence_id, request.user)
        if err:
            return err
        try:
            os_type = evidence.os  # "windows" or "linux"

            # Load from both JSON files
            with open("volatility_engine/volweb_plugins.json", "r") as f:
                main_plugins = json.load(f).get("plugins", {}).get(os_type, {})
            with open("volatility_engine/volweb_misc.json", "r") as f:
                misc_plugins = json.load(f).get("plugins", {}).get(os_type, {})

            # Build a map of already-executed plugins for this evidence
            executed_plugins = {}
            for p in VolatilityPlugin.objects.filter(evidence=evidence):
                if p.error_message and "timed out" in p.error_message.lower():
                    executed_plugins[p.name] = "timed_out"
                elif p.error_message:
                    executed_plugins[p.name] = "failed"
                elif p.results:
                    executed_plugins[p.name] = "success"
                else:
                    executed_plugins[p.name] = "no_output"

            # Group by category
            categories = {}
            for name, details in main_plugins.items():
                category = details.get("category", "Other")
                if category not in categories:
                    categories[category] = []
                categories[category].append({
                    "name": name,
                    "icon": details.get("icon", ""),
                    "description": details.get("description", ""),
                    "display": details.get("display", "True"),
                    "source": "main",
                    "execution_status": executed_plugins.get(name, None),
                })
            for name, details in misc_plugins.items():
                category = details.get("category", "Other")
                if category not in categories:
                    categories[category] = []
                categories[category].append({
                    "name": name,
                    "icon": details.get("icon", ""),
                    "description": details.get("description", ""),
                    "display": details.get("display", "True"),
                    "source": "misc",
                    "execution_status": executed_plugins.get(name, None),
                })

            total = len(main_plugins) + len(misc_plugins)

            return Response({
                "os": os_type,
                "categories": categories,
                "total_plugins": total,
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SelectiveExtractionTask(APIView):
    """
    Starts extraction with only the selected plugins.
    Required plugins (PsList, PsTree) are automatically included.
    """
    permission_classes = (IsAuthenticated,)

    REQUIRED_PLUGINS = {
        "windows": [
            "volatility3.plugins.windows.pslist.PsList",
            "volatility3.plugins.windows.pstree.PsTree",
        ],
        "linux": [
            "volatility3.plugins.linux.pslist.PsList",
            "volatility3.plugins.linux.pstree.PsTree",
        ],
    }

    def post(self, request):
        evidence_id = request.data.get("id")
        if not evidence_id:
            return Response({"error": "Evidence ID is required"}, status=status.HTTP_400_BAD_REQUEST)

        selected_plugins = request.data.get("plugins", [])
        if not selected_plugins:
            return Response({"error": "At least one plugin must be selected"}, status=status.HTTP_400_BAD_REQUEST)

        evidence, err = _get_evidence_or_403(evidence_id, request.user)
        if err:
            return err

        # Gate Linux extraction on kernel-symbol readiness: without a matching
        # ISF the Linux plugins cannot run.
        if evidence.os == "linux":
            from .models import LinuxSymbolResolution
            resolution = LinuxSymbolResolution.objects.filter(evidence=evidence).first()
            if not resolution or resolution.status != "ready":
                return Response(
                    {"error": "Kernel symbols (ISF) are not ready for this Linux evidence. "
                              "Wait for automatic resolution to finish or upload a matching ISF."},
                    status=status.HTTP_409_CONFLICT,
                )

        try:
            run_timeliner = request.data.get("run_timeliner", False)
            pid_filter = request.data.get("pid", None)
            skip_completed = request.data.get("skip_completed", False)
            plugin_timeout = request.data.get("plugin_timeout", None)

            # Merge required plugins into selection
            required = self.REQUIRED_PLUGINS.get(evidence.os, [])
            merged_plugins = list(set(selected_plugins + required))

            result = start_selective_extraction.apply_async(
                args=[evidence.id],
                kwargs={
                    "selected_plugins": merged_plugins,
                    "pid_filter": int(pid_filter) if pid_filter else None,
                    "skip_completed": skip_completed,
                    "plugin_timeout": int(plugin_timeout) if plugin_timeout else None,
                }
            )

            evidence.celery_task_id = result.id
            evidence.save(update_fields=["celery_task_id"])

            if run_timeliner:
                start_timeliner.apply_async(args=[evidence.id])

            return Response({"message": "Selective extraction started"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class EvidenceLootView(APIView):
    """
    Inventory of the artefact files a plugin run or an on-demand dump wrote to
    disk for an evidence (media/{id}/)
    """

    permission_classes = (IsAuthenticated,)

    # Files that live in the evidence media dir but are internal result stores,
    # not user-facing forensic artefacts.
    EXCLUDED_NAMES = {"yarascan_results.jsonl"}

    def _evidence_dir(self, evidence_id):
        return os.path.realpath(os.path.join(settings.MEDIA_ROOT, str(evidence_id)))

    def get(self, request, evidence_id):
        evidence, err = _get_evidence_or_403(evidence_id, request.user)
        if err:
            return err

        base_dir = self._evidence_dir(evidence_id)
        artefacts = []
        if os.path.isdir(base_dir):
            with os.scandir(base_dir) as entries:
                for entry in entries:
                    if not entry.is_file() or entry.name in self.EXCLUDED_NAMES:
                        continue
                    stat = entry.stat()
                    artefacts.append({
                        "name": entry.name,
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(
                            stat.st_mtime, tz=timezone.utc
                        ).isoformat(),
                        "url": f"/media/{evidence_id}/{entry.name}",
                    })

        artefacts.sort(key=lambda a: a["modified"], reverse=True)
        total_size = sum(a["size"] for a in artefacts)
        return Response(
            {"count": len(artefacts), "total_size": total_size, "artefacts": artefacts},
            status=status.HTTP_200_OK,
        )

    def delete(self, request, evidence_id):
        evidence, err = _get_evidence_or_403(evidence_id, request.user)
        if err:
            return err

        name = request.data.get("name")
        if not name:
            return Response({"error": "name is required"}, status=status.HTTP_400_BAD_REQUEST)

        base_dir = self._evidence_dir(evidence_id)
        target = os.path.realpath(os.path.join(base_dir, name))

        # Reject anything that escapes the evidence directory (path traversal)
        # or targets the directory itself / an excluded internal file.
        if (
            os.path.commonpath([base_dir, target]) != base_dir
            or target == base_dir
            or os.path.basename(target) in self.EXCLUDED_NAMES
        ):
            return Response({"error": "Invalid file name"}, status=status.HTTP_400_BAD_REQUEST)

        if not os.path.isfile(target):
            return Response({"error": "Artefact not found"}, status=status.HTTP_404_NOT_FOUND)

        try:
            os.remove(target)
        except OSError as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"message": "Artefact deleted"}, status=status.HTTP_200_OK)


class IsfResolutionView(APIView):
    """
    Linux kernel-symbol (ISF) resolution status for an evidence, and a retry
    trigger. Windows evidences are always reported as ready (symbols bundled).
    """
    permission_classes = (IsAuthenticated,)

    def get(self, request, evidence_id):
        evidence, err = _get_evidence_or_403(evidence_id, request.user)
        if err:
            return err
        if evidence.os != "linux":
            return Response({"status": "ready", "banner": None, "guidance": None, "message": None})
        from .models import LinuxSymbolResolution
        resolution = LinuxSymbolResolution.objects.filter(evidence=evidence).first()
        if not resolution:
            return Response({"status": "pending", "banner": None, "guidance": None, "message": None})
        return Response({
            "status": resolution.status,
            "banner": resolution.banner,
            "method": resolution.method,
            "guidance": resolution.guidance,
            "message": resolution.message,
        })

    def post(self, request, evidence_id):
        evidence, err = _get_evidence_or_403(evidence_id, request.user)
        if err:
            return err
        if evidence.os != "linux":
            return Response({"error": "Not a Linux evidence"}, status=status.HTTP_400_BAD_REQUEST)
        from .tasks import generate_linux_symbols
        generate_linux_symbols.delay(evidence.id)
        return Response({"message": "ISF resolution restarted"}, status=status.HTTP_200_OK)