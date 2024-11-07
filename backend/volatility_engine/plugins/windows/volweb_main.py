import json
import logging
import importlib
from typing import Dict, Any, List, Tuple, Optional
from volatility3.framework import interfaces
from volatility3.framework.interfaces import plugins
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import TreeGrid
from volatility_engine.utils import DjangoRenderer, file_handler
from volatility_engine.models import VolatilityPlugin
from evidences.models import Evidence

vollog = logging.getLogger(__name__)


class VolWebMain(plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)


    def load_plugin_info(self, json_file_path):
        with open(json_file_path, "r") as file:
            return json.load(file).get("plugins", {}).get("windows", [])

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
        ]

    def dynamic_import(self, module_name):
        module_path, class_name = module_name.rsplit(".", 1)
        module = importlib.import_module(module_path)
        return getattr(module, class_name)

    def run_all(self):
        volweb_plugins = self.load_plugin_info("volatility_engine/volweb_plugins.json")

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

        evidence_id = self.context.config["VolWeb.Evidence"]
        evidence = Evidence.objects.get(id=evidence_id)
        count = 0
        total = len(instances.items())
        for name, plugin in instances.items():
            try:
                vollog.info(f"RUNNING: {name}")
                self.context.config["plugins.VolWebMain.dump"] = (
                    False  # No dump by default
                )
                if name == "volatility3.plugins.windows.registry.hivelist.HiveList":
                    self.context.config["plugins.VolWebMain.dump"] = (
                        True  # We want to dump the hivelist
                    )
                plugin["class"]._file_handler = file_handler(
                    f"media/{evidence_id}/"
                )  # Our file_handler need to be passed to the sub-plugin
                self._grid = plugin["class"].run()
                renderer = DjangoRenderer(
                    evidence_id=evidence_id, plugin=plugin["details"]
                )  # Render the output of each plugin in the django database
                renderer.render(self._grid)
                evidence.status = (count*100)/total
                count += 1
                evidence.save()
            except:
                pass

    def _generator(self):
        yield (0, ("Success",))

    def run(self):
        self.run_all()
        return TreeGrid(
            [("Status", str)],
            self._generator(),
        )
