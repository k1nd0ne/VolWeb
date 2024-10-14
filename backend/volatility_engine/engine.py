from evidences.models import Evidence
from .models import VolatilityPlugin
from celery import shared_task
import logging, os, json
import volatility3
from volatility3.cli import MuteProgress
from volatility3.framework import contexts
from volatility3 import plugins
from volatility3.framework.exceptions import UnsatisfiedException
from .utils import DictRenderer, file_handler, volweb_open
from volatility3.framework.plugins import construct_plugin
from volatility3.framework import automagic
volatility3.framework.require_interface_version(2, 0, 0)
logger = logging.getLogger(__name__)


class VolatiltiyEngine:
    def __init__(self, evidence) -> None:
        try:
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
            failures = volatility3.framework.import_files(plugins, True)
            if failures:
                logger.error(f"Some volatility3 plugin couldn't be loaded : {failures}")
            else:
                logger.info(f"Volatility3 Plugins are loaded without failure")

            self.volatility_plugins = volatility3.framework.list_plugins()
            with open("./volatility_engine/volweb_plugins.json", "r") as file:
                self.volweb_plugins = json.load(file)
            self.constructed_plugins = {}
            self.build_context()

        except Exception as e:
            logger.error(f"An error occurred during initialization: {str(e)}")

    def build_context(self):
        try:
            self.context = contexts.Context()
            available_automagics = automagic.available(self.context)
            # Choose a dummy plugin to choose the automagic ones
            # Not really elegant
            if self.evidence.os == "windows":
                dummy_plugin = "windows.info.Info"
            else:
                dummy_plugin = "linux.psscan.PsScan"

            self.automagics = automagic.choose_automagic(
                available_automagics, self.volatility_plugins[dummy_plugin]
            )
            self.context.config["automagic.LayerStacker.stackers"] = (
                automagic.stacker.choose_os_stackers(
                    self.volatility_plugins[dummy_plugin]
                )
            )
            self.context.config["automagic.LayerStacker.single_location"] = (
                self.evidence_data["bucket"]
            )
            # Construct plugins
            for plugin in self.volweb_plugins[self.evidence.os]:
                try:
                    constructed = construct_plugin(
                        self.context,
                        self.automagics,
                        self.volatility_plugins[plugin["name"]],
                        self.base_config_path,
                        MuteProgress(),
                        file_handler(""),
                    )
                    if constructed:
                        self.constructed_plugins[plugin["name"]] = {
                        "constructed": constructed,
                        "description": plugin["description"],
                        "icon": plugin["icon"]
                        }
                except UnsatisfiedException:
                    continue
        except Exception as e:
            logger.error(f"An error occurred during context building: {str(e)}")

    def run_plugin(self, constructed):
        """
        Simple method to run a volatility3 plugin
        """
        try:
            result = DictRenderer().render(constructed.run())
            return result
        except Exception as e:
            logger.error(f"An error occurred while running the plugin: {str(e)}")
            return None

    def start_extraction(self):
        try:
            logger.info("Starting extraction")
            self.evidence.status = 0  # Make sure we start at 0%
            completed_task = 0
            # Iterate over each compatible plugins and run them
            for plugin_name, constructed in self.constructed_plugins.items():
                print(f"running plugin: {plugin_name}")
                artefacts = self.run_plugin(constructed["constructed"])
                # Create a VolatilityPlugin entry in the database
                VolatilityPlugin(
                    name=plugin_name, description=constructed["description"], icon=constructed["icon"], evidence=self.evidence, artefacts=artefacts
                ).save()
                completed_task = completed_task + 1
                self.evidence.status = (completed_task * 100) / len(
                    self.constructed_plugins.keys()
                )
                self.evidence.save()
            self.evidence.status = 100
            self.evidence.save()
        except Exception as e:
            logger.error(f"An error occurred during extraction: {str(e)}")
