from evidences.models import Evidence
from .models import VolatilityPlugin, EnrichedProcess
from celery import shared_task
import logging, os, json
import volatility3
from volatility3.cli import MuteProgress
from volatility3.framework import contexts, automagic, constants
from volatility3.framework.exceptions import UnsatisfiedException
from .utils import (
    DictRenderer,
    file_handler,
    volweb_open,
    DjangoRenderer,
    build_timeline,
    fix_permissions,
)
from volatility3.plugins.linux.pslist import PsList
from volatility3.plugins.linux.proc import Maps
from volatility3.framework.plugins import construct_plugin
from .plugins.windows.volweb_main import VolWebMain as VolWebMainW
from .plugins.windows.volweb_misc import VolWebMisc as VolWebMiscW
from .plugins.linux.volweb_main import VolWebMain as VolWebMainL
from .plugins.linux.volweb_misc import VolWebMisc as VolWebMiscL
from volatility3.plugins.windows.dumpfiles import DumpFiles

volatility3.framework.require_interface_version(2, 0, 0)
logger = logging.getLogger(__name__)


class VolatilityEngine:
    """
    The Volatility3 Engine is a modular class to enable the execution multiple volatility3 plugins.
    It is used by VolWeb when a user just uploaded a memory image for a given Evidence
    """

    def __init__(self, evidence) -> None:
        """ """
        self.evidence: Evidence = evidence
        # Checks if the user bind an evidence or is using the default storage solution
        if self.evidence.url:
            self.evidence_data = {
                "bucket": self.evidence.url,
                "output_path": f"media/{self.evidence.id}/",
            }
        else:
            self.evidence_data = {
                "bucket": f"s3://{self.evidence.linked_case.bucket_id}/{self.evidence.name}",
                "output_path": f"media/{self.evidence.id}/",
            }
        self.base_config_path = "plugins"


    def build_context(self, plugin):
        self.plugin, self.metadata = plugin.popitem()

        self.context = contexts.Context()
        available_automagics = automagic.available(self.context)

        self.automagics = automagic.choose_automagic(available_automagics, self.plugin)
        self.context.config["automagic.LayerStacker.stackers"] = (
            automagic.stacker.choose_os_stackers(self.plugin)
        )

        self.context.config["automagic.LayerStacker.single_location"] = (
            self.evidence_data["bucket"]
        )

        self.context.config["VolWeb.Evidence"] = self.evidence.id

    def construct_plugin(self):
        """
        This Method can be used to execute any plugins this will:
            - Create a new context
            - Choose the automagics
            - Construct the plugin
            - Put the result inside the django database using our custom renderer
        """
        constructed = construct_plugin(
            self.context,
            self.automagics,
            self.plugin,
            self.base_config_path,
            MuteProgress(),
            file_handler(self.evidence_data["output_path"]),
        )
        return constructed

    def run_plugin(self, constructed):
        if constructed:
            result = DjangoRenderer(self.evidence.id, self.metadata).render(
                constructed.run()
            )
            return result
        return None

    def start_windows_analysis(self):
        plugin_list = [
            {
                VolWebMainW: {
                    "icon": "None",
                    "description": "VolWeb Main plugin executing many other plugins with automagics optimization",
                    "category": "Other",
                    "display": "False",
                    "name": "VolWebMain",
                }
            },
            {
                VolWebMiscW: {
                    "icon": "None",
                    "description": "VolWeb Misc plugin executing other plugins that are sharing the same requirements with automagics optimization",
                    "category": "Other",
                    "display": "False",
                    "name": "VolWebMisc",
                }
            },
        ]
        for plugin in plugin_list:
            logger.debug(f"Running {plugin}...")
            self.build_context(plugin)
            builted_plugin = self.construct_plugin()
            self.run_plugin(builted_plugin)
        fix_permissions(self.evidence_data["output_path"])

    def start_linux_analysis(self):
        plugin_list = [
            {
                VolWebMainL: {
                    "icon": "None",
                    "description": "VolWeb Main plugin executing many other plugins with automagics optimization",
                    "category": "Other",
                    "display": "False",
                    "name": "VolWebMain",
                }
            },
            {
                VolWebMiscL: {
                    "icon": "None",
                    "description": "VolWeb Misc plugin executing other plugins that are sharing the same requirements with automagics optimization",
                    "category": "Other",
                    "display": "False",
                    "name": "VolWebMisc",
                }
            },
        ]
        for plugin in plugin_list:
            logger.debug(f"RUNNING PLUGIN: {plugin}")
            self.build_context(plugin)
            builted_plugin = self.construct_plugin()
            self.run_plugin(builted_plugin)
        fix_permissions(self.evidence_data["output_path"])


    def start_timeliner(self):
        timeliner_plugin = {
             volatility3.plugins.timeliner.Timeliner: {
                "icon": "None",
                "description": "VolWeb main plugin executing many other plugins with automagics optimization",
                "category": "Other",
                "display": "False",
                "name": "volatility3.plugins.timeliner.Timeliner",
            }
        }
        self.build_context(timeliner_plugin)
        builted_plugin = self.construct_plugin()
        result = self.run_plugin(builted_plugin)
        if result:
            graph = build_timeline(result)
            VolatilityPlugin(
                name="volatility3.plugins.timeliner.TimelinerGraph",
                icon="None",
                description="None",
                evidence=self.evidence,
                artefacts=graph,
                category="Timeline",
                display="False",
                results=True,
            ).save()

    def start_extraction(self):
        try:
            logger.info("Starting extraction")
            self.evidence.status = 0  # Make sure we start at 0%
            if self.evidence.os == "windows":
                self.start_windows_analysis()
                self.construct_windows_explorer()
            else:
                self.start_linux_analysis()
        except UnsatisfiedException as e:
            logger.warning(f"Unsatisfied requirements: {str(e)}")

    def dump_process(self, pid):
        logger.info(f"Trying to dump PID {pid}")
        if self.evidence.os == "windows":
            pslist_plugin = {
                volatility3.plugins.windows.pslist.PsList: {
                    "icon": "N/A",
                    "description": "N/A",
                    "category": "Processes",
                    "display": "False",
                    "name": f"volatility3.plugins.windows.pslist.PsListDump.{pid}",
                }
            }
        else:
            pslist_plugin = {
                PsList: {
                    "icon": "N/A",
                    "description": "N/A",
                    "category": "Processes",
                    "display": "False",
                    "name": f"volatility3.plugins.linux.pslist.PsListDump.{pid}",
                }
            }
        self.build_context(pslist_plugin)
        self.context.config["plugins.PsList.pid"] = [
            pid,
        ]
        self.context.config["plugins.PsList.dump"] = True
        builted_plugin = self.construct_plugin()
        result = self.run_plugin(builted_plugin)
        return result


    def dump_process_maps(self, pid):
        logger.info(f"Trying to dump PID {pid}")
        if self.evidence.os == "windows":
            procmaps_plugin = {
                volatility3.plugins.windows.pslist.PsList: {
                    "icon": "N/A",
                    "description": "N/A",
                    "category": "Processes",
                    "display": "False",
                    "name": f"volatility3.plugins.windows.pslist.PsListDump.{pid}",
                }
            }
        else:
            procmaps_plugin = {
                Maps: {
                    "icon": "N/A",
                    "description": "N/A",
                    "category": "Processes",
                    "display": "False",
                    "name": f"volatility3.plugins.linux.proc.MapsDump.{pid}",
                }
            }
        self.build_context(procmaps_plugin)
        self.context.config["plugins.Maps.pid"] = [
            pid,
        ]
        self.context.config["plugins.Maps.dump"] = True
        builted_plugin = self.construct_plugin()
        result = self.run_plugin(builted_plugin)
        return result


    def compute_handles(self, pid):
        handles_plugin = {
            volatility3.plugins.windows.handles.Handles: {
                "icon": "N/A",
                "description": "N/A",
                "category": "Processes",
                "display": "False",
                "name": f"volatility3.plugins.windows.handles.Handles.{pid}",
            }
        }
        self.build_context(handles_plugin)
        self.context.config["plugins.Handles.pid"] = [int(pid)]
        builted_plugin = self.construct_plugin()
        result = self.run_plugin(builted_plugin)

    def dump_file(self, offset):
        dumpfiles_plugin = {
            DumpFiles: {
                "icon": "N/A",
                "description": "N/A",
                "category": "Processes",
                "display": "False",
                "name": f"volatility3.plugins.dumpfiles.DumpFiles.{offset}",
            }
        }
        self.build_context(dumpfiles_plugin)
        self.context.config["plugins.DumpFiles.virtaddr"] = int(offset)
        builted_plugin = self.construct_plugin()
        try:
            result = self.run_plugin(builted_plugin)
            if not result:
                del self.context.config["plugins.DumpFiles.virtaddr"]
                self.context.config["plugins.DumpFiles.physaddr"] = int(offset)
                result = self.run_plugin(builted_plugin)

            fix_permissions(f"media/{self.evidence.id}")
            return result
        except Exception as e:
            logger.error(e)
            return None


    def construct_windows_explorer(self):
        # Get all VolatilityPlugin objects linked to this evidence
        plugins = VolatilityPlugin.objects.filter(evidence=self.evidence)

        # Get the pslist plugin's output, which contains the list of processes
        try:
            pslist_plugin = VolatilityPlugin.objects.get(
                evidence=self.evidence,
                name="volatility3.plugins.windows.pslist.PsList"
            )
        except VolatilityPlugin.DoesNotExist:
            logger.error("pslist plugin not found for this evidence")
            return

        pslist_artefacts = pslist_plugin.artefacts  # This should be a list of process dicts

        # Iterate over each process in pslist
        for process in pslist_artefacts:
            pid = process.get("PID") or process.get("Process ID")
            if pid is None:
                continue  # Skip if no PID
            pid = int(pid)

            # Initialize enriched process data with pslist data
            enriched_process_data = {'pslist': process}

            # Iterate over other plugins linked to the same evidence
            for plugin in plugins.exclude(id=pslist_plugin.id):
                artefacts = plugin.artefacts
                if not artefacts:
                    continue
                # Check if the PID matches in the plugin's artefacts
                for artefact in artefacts:
                    plugin_pid = artefact.get("PID") or artefact.get("Process ID")
                    if plugin_pid and int(plugin_pid) == pid:
                        # Ensure enriched process data contains an array of artefacts
                        if plugin.name not in enriched_process_data:
                            enriched_process_data[plugin.name] = []
                        # Append the artefact to the array
                        enriched_process_data[plugin.name].append(artefact)

            # Save the enriched process data into the EnrichedProcess model
            EnrichedProcess.objects.update_or_create(
                evidence=self.evidence,
                pid=pid,
                defaults={'data': enriched_process_data}
            )
