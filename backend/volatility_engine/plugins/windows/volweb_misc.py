import json
import logging
import importlib
from typing import Dict, Any, List, Tuple, Optional
from volatility3.framework import interfaces
from volatility3.framework.interfaces import plugins
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import TreeGrid
from volatility_engine.utils import DjangoRenderer
from volatility_engine.models import VolatilityPlugin
from volatility3.plugins import yarascan

vollog = logging.getLogger(__name__)


class VolWebMisc(plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    def load_plugin_info(self, json_file_path):
        with open(json_file_path, "r") as file:
            return json.load(file).get("plugins", {}).get("windows", [])

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory layer for the kernel",
                architectures=["Intel32", "Intel64"],
            )
        ]

    def dynamic_import(self, module_name):
        module_path, class_name = module_name.rsplit(".", 1)
        module = importlib.import_module(module_path)
        return getattr(module, class_name)

    def run_all(self):
        volweb_plugins = self.load_plugin_info("volatility_engine/volweb_misc.json")
        instances = {}
        for plugin, details in volweb_plugins.items():
            try:
                plugin_class = self.dynamic_import(plugin)
                instances[plugin] = {
                    "class": plugin_class(self.context, self.config_path),
                    "details": details,
                }
                instances[plugin]["details"]["name"] = plugin
            except ImportError as e:
                vollog.error(f"Could not import {plugin}: {e}")

        for name, plugin in instances.items():
            vollog.info(f"RUNNING: {name}")
            self._grid = plugin["class"].run()
            renderer = DjangoRenderer(
                evidence_id=self.context.config["VolWeb.Evidence"],
                plugin=plugin["details"],
            )
            renderer.render(self._grid)

    def _generator(self):
        yield (0, ("Success",))

    def run(self):
        self.run_all()
        return TreeGrid(
            [("Status", str)],
            self._generator(),
        )
