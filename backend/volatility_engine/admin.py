import json
import logging

from django.contrib import admin
from django.template.response import TemplateResponse
from django.urls import path

from .models import VolatilityPlugin, EnrichedProcess

logger = logging.getLogger(__name__)

_CURATED_FILES = (
    "volatility_engine/volweb_plugins.json",
    "volatility_engine/volweb_misc.json",
)


def _curated_names(os_name):
    """Set of curated plugin names (full dotted paths) for an OS."""
    names = set()
    for fname in _CURATED_FILES:
        try:
            with open(fname) as fh:
                data = json.load(fh)
            names.update((data.get("plugins", {}).get(os_name, {}) or {}).keys())
        except Exception as e:
            logger.warning(f"Could not read curated plugins from {fname}: {e}")
    return names


def _installed_names_by_os():
    """
    Plugin names actually exposed by the installed volatility3, grouped by OS
    and normalized to the same full dotted path used in the curated JSON.
    """
    from volatility3 import framework
    import volatility3.plugins

    framework.import_files(volatility3.plugins, True)
    result = {"windows": set(), "linux": set()}
    for short_name in framework.list_plugins().keys():
        # YARA scanning plugins (yarascan / vadyarascan / vmayarascan) have their
        # own dedicated flow in VolWeb, not the curated selector — skip them.
        if "yarascan" in short_name.lower():
            continue
        for os_name in result:
            if short_name.startswith(f"{os_name}."):
                result[os_name].add(f"volatility3.plugins.{short_name}")
    return result


def _deprecated_aliases(available):
    """
    Top-level plugins that are just deprecated aliases of a plugin moved into a
    subpackage (``<os>.<module>`` when ``<os>.malware.<module>`` or
    ``<os>.registry.<module>`` also exists). These are noise in the diff.
    """
    sub_modules = set()
    for name in available:
        parts = name[len("volatility3.plugins."):].split(".")
        if len(parts) >= 3 and parts[1] in ("malware", "registry"):
            sub_modules.add(f"{parts[0]}.{parts[1]}.{parts[2]}")

    deprecated = set()
    for name in available:
        parts = name[len("volatility3.plugins."):].split(".")
        if len(parts) == 3:  # os.module.Class (top-level)
            if any(f"{parts[0]}.{sub}.{parts[1]}" in sub_modules for sub in ("malware", "registry")):
                deprecated.add(name)
    return deprecated


class VolatilityPluginAdmin(admin.ModelAdmin):
    change_list_template = "admin/volatility_engine/volatilityplugin/change_list.html"

    def get_urls(self):
        custom = [
            path(
                "plugins-diff/",
                self.admin_site.admin_view(self.plugins_diff_view),
                name="volatility_engine_plugins_diff",
            ),
        ]
        return custom + super().get_urls()

    def plugins_diff_view(self, request):
        """
        Maintenance helper: diff the curated plugin list against the plugins
        actually exposed by the *installed* volatility3, so the curated JSON can
        be updated deliberately when the pinned volatility3 version is bumped.
        Read-only; does not affect extraction.
        """
        error = None
        report = {}
        try:
            installed = _installed_names_by_os()
            for os_name in ("windows", "linux"):
                curated = _curated_names(os_name)
                available = installed.get(os_name, set())
                deprecated = _deprecated_aliases(available)
                report[os_name] = {
                    # in vol3, not curated, and not a deprecated alias -> real candidates
                    "missing": sorted((available - curated) - deprecated),
                    "stale": sorted(curated - available),     # curated, gone from vol3 -> fix/remove
                    "deprecated_hidden": len(deprecated & (available - curated)),
                    "curated_count": len(curated),
                    "available_count": len(available),
                }
        except Exception as e:
            logger.exception("Plugin diff failed")
            error = str(e)

        context = {
            **self.admin_site.each_context(request),
            "title": "Volatility plugins — curated vs installed",
            "report": report,
            "error": error,
        }
        return TemplateResponse(
            request, "admin/volatility_engine/plugins_diff.html", context
        )


admin.site.register(VolatilityPlugin, VolatilityPluginAdmin)
admin.site.register(EnrichedProcess)
