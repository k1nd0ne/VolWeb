from evidences.models import Evidence
from .models import VolatilityPlugin
from celery import shared_task
import logging, os, json
import volatility3
from volatility3.cli import MuteProgress
from volatility3.framework import contexts, automagic, constants
from volatility3.framework.exceptions import UnsatisfiedException
from .utils import DictRenderer, file_handler, volweb_open
from volatility3.framework.plugins import construct_plugin
from .plugins.windows.volweb import VolWeb


volatility3.framework.require_interface_version(2, 0, 0)
logger = logging.getLogger(__name__)


class VolatiltiyEngine:
    def __init__(self, evidence) -> None:
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
        self.build_context()

    def build_context(self):
        self.context = contexts.Context()
        available_automagics = automagic.available(self.context)
        # Choose a dummy plugin to choose the automagic ones
        # Not really elegant
        if self.evidence.os == "windows":
            dummy_plugin = VolWeb # TODO Create a Windows and Linux Plugin
        else:
            print("TODO")
            exit(1)
        self.automagics = automagic.choose_automagic(
            available_automagics, VolWeb
        )
        self.context.config["automagic.LayerStacker.stackers"] = (
            automagic.stacker.choose_os_stackers(
                VolWeb
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
            VolWeb,
            self.base_config_path,
            MuteProgress(),
            file_handler(""),
        )
        if constructed:
            result = DictRenderer().render(constructed.run())

    def start_extraction(self):
        try:
            logger.info("Starting extraction")
            self.evidence.status = 0  # Make sure we start at 0%
            completed_task = 0
        except Exception as e:
            logger.error(f"An error occurred during extraction: {str(e)}")
