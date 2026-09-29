import json
import logging
import importlib
import signal
import time
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

        # Filter to selected plugins if specified via context config
        selected_json = self.context.config.get("VolWeb.SelectedPlugins", None)
        if selected_json:
            selected = json.loads(selected_json)
            volweb_plugins = {
                name: details for name, details in volweb_plugins.items()
                if name in selected
            }

        # Read optional PID filter
        pid_filter = self.context.config.get("VolWeb.PidFilter", None)

        try:
            kernel_module = self.context.modules[self.config["kernel"]]
            self.context.config[f"{self.config_path}.primary"] = kernel_module.layer_name
        except Exception as e:
            vollog.warning(f"Could not expose 'primary' layer for layer-scanning plugins: {e}")

        instances = {}
        failed_plugins = []
        for plugin, details in volweb_plugins.items():
            plugin_class = None
            try:
                plugin_class = self.dynamic_import(plugin)
                instances[plugin] = {
                    "class": plugin_class(self.context, self.config_path),
                    "details": details,
                }
                instances[plugin]["details"]["name"] = plugin
            except ImportError as e:
                vollog.error(f"Could not import {plugin}: {e}")
            except Exception as e:
                try:
                    unmet = plugin_class.unsatisfied(self.context, self.config_path)
                    unmet_desc = ", ".join(sorted(unmet.keys())) if unmet else "unknown"
                except Exception:
                    unmet_desc = "unknown"
                vollog.error(
                    f"Skipping plugin {plugin}: failed to validate; "
                    f"unsatisfied requirements: [{unmet_desc}] ({e})"
                )
                failed_plugins.append(
                    (plugin, details, f"Unsatisfied requirements: {unmet_desc}")
                )

        evidence_id = self.context.config["VolWeb.Evidence"]
        evidence = Evidence.objects.get(id=evidence_id)

        for name, details, err in failed_plugins:
            VolatilityPlugin.objects.update_or_create(
                name=name,
                evidence=evidence,
                defaults={
                    "icon": details.get("icon"),
                    "description": details.get("description"),
                    "category": details.get("category", "Other"),
                    "display": details.get("display", "True"),
                    "artefacts": None,
                    "results": False,
                    "error_message": f"Plugin failed to construct/validate: {err}",
                },
            )

        # Read optional per-plugin timeout (in seconds)
        plugin_timeout = self.context.config.get("VolWeb.PluginTimeout", None)

        count = 0
        total = len(instances.items())
        for name, plugin in instances.items():
            # Pause/Stop check
            evidence.refresh_from_db()
            while evidence.extraction_control == "paused":
                time.sleep(3)
                evidence.refresh_from_db()
                if evidence.extraction_control == "stop_requested":
                    break
            if evidence.extraction_control == "stop_requested":
                vollog.info(f"Stop requested — halting extraction for evidence {evidence_id}")
                break

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
                if plugin_timeout:
                    def _timeout_handler(signum, frame):
                        raise TimeoutError(f"Plugin timed out after {plugin_timeout} seconds")
                    old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
                    signal.alarm(int(plugin_timeout))
                    try:
                        self._grid = plugin["class"].run()
                        renderer = DjangoRenderer(
                            evidence_id=evidence_id, plugin=plugin["details"]
                        )
                        renderer.render(self._grid)
                    finally:
                        signal.alarm(0)
                        signal.signal(signal.SIGALRM, old_handler)
                else:
                    self._grid = plugin["class"].run()
                    renderer = DjangoRenderer(
                        evidence_id=evidence_id, plugin=plugin["details"]
                    )
                    renderer.render(self._grid)
                evidence.status = (count * 100) / total
                count += 1
                evidence.refresh_from_db(fields=["extraction_control"])
                evidence.save(update_fields=["status"])
            except Exception as e:
                vollog.error(f"FAILED: {name}: {e}")
                VolatilityPlugin.objects.update_or_create(
                    name=name,
                    evidence=evidence,
                    defaults={
                        "icon": plugin["details"].get("icon", "None"),
                        "description": plugin["details"].get("description", ""),
                        "artefacts": None,
                        "category": plugin["details"].get("category", "Other"),
                        "display": plugin["details"].get("display", "True"),
                        "results": False,
                        "error_message": str(e),
                    },
                )
                count += 1

    def _generator(self):
        yield (0, ("Success",))

    def run(self):
        self.run_all()
        return TreeGrid(
            [("Status", str)],
            self._generator(),
        )
