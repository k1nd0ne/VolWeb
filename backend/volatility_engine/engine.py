from evidences.models import Evidence
from .models import VolatilityPlugin
from celery import shared_task
import logging, os, json
import volatility3
from volatility3.cli import MuteProgress
from volatility3.framework import contexts, automagic, constants
from volatility3.framework.exceptions import UnsatisfiedException
from .utils import DictRenderer, file_handler, volweb_open, DjangoRenderer
from volatility3.framework.plugins import construct_plugin
from volatility3.plugins.windows import (
    mftscan,
    ssdt,
)
from .plugins.windows.volweb_main import VolWebMain
from .plugins.windows.volweb_misc import VolWebMisc

volatility3.framework.require_interface_version(2, 0, 0)
logger = logging.getLogger(__name__)


class VolatiltiyEngine:
    """
    The Volatility3 Engine is a modular class to enable the execution multiple volatility3 plugins.
    It is used by VolWeb when a user just uploaded a memory image for a given Evidence
    """
    def __init__(self, evidence) -> None:
        """
        """
        self.evidence: Evidence = evidence
        # Checks if the user bind an evidence or is using the default storage solution
        if self.evidence.url:
            self.evidence_data = {
                "bucket": self.evidence.url,
                "output_path": "",
            }
        else:
            self.evidence_data = {
                "bucket": f"s3://{self.evidence.linked_case.bucket_id}/{self.evidence.name}",
                "output_path": "",
            }
        self.base_config_path = "plugins"

    def run_plugin(self, plugin):
        """
        This Method can be used to execute any plugins this will:
            - Create a new context
            - Choose the automagics
            - Construct the plugin
            - Put the result inside the django database using our custom renderer
        """
        plugin, metadata = plugin.popitem()

        self.context = contexts.Context()
        available_automagics = automagic.available(self.context)

        self.automagics = automagic.choose_automagic(
            available_automagics, plugin
        )
        self.context.config["automagic.LayerStacker.stackers"] = (
            automagic.stacker.choose_os_stackers(
                plugin
            )
        )

        self.context.config["automagic.LayerStacker.single_location"] = (
            self.evidence_data["bucket"]
        )

        self.context.config["VolWeb.Evidence"] = (
            self.evidence.id
        )

        constructed = construct_plugin(
            self.context,
            self.automagics,
            plugin,
            self.base_config_path,
            MuteProgress(),
            file_handler(""),
        )
        if constructed:
            result = DjangoRenderer(self.evidence.id, metadata).render(constructed.run())

    def start_windows_analysis(self):
        plugin_list = [
            {
                VolWebMain: {
                  "icon": "AccountTree",
                  "description": "VolWeb Main plugin executing many other plugins with automagics optimization",
                  "category": "Other",
                  "display": "False",
                  "name": "VolWebMain"
                }
            },
            {
                VolWebMisc: {
                  "icon": "AccountTree",
                  "description": "VolWeb Misc plugin executing other plugins that are sharing the same requirements with automagics optimization",
                  "category": "Other",
                  "display": "False",
                  "name": "VolWebMisc"
                }
            },
        ]
        for plugin in plugin_list:
            logger.info(f"RUNNING PLUGIN: {plugin}")
            self.run_plugin(plugin)

    def start_extraction(self):
        try:
            logger.info("Starting extraction")
            self.evidence.status = 0  # Make sure we start at 0%
            completed_task = 0
            if self.evidence.os == "windows":
                self.start_windows_analysis()
        except UnsatisfiedException as e:
            logger.info(f"Unsatisfied requirements: {str(e)}")

    def start_timeliner(self):
        try:
            logger.info('Starting timeliner')
            self.start_timeliner()
        except:
            logger.info("Could not execute the timeliner plugin")
