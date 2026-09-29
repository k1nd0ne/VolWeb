from evidences.models import Evidence
from yararules.models import YaraRule
from yararulesets.models import YaraRuleSet
from .models import VolatilityPlugin, EnrichedProcess
import logging
import volatility3
import traceback
import os
import re
import json
import shutil
from volatility3.cli import MuteProgress
from volatility3.framework.exceptions import UnsatisfiedException
from .utils import (
    file_handler,
    DjangoRenderer,
    build_timeline,
    fix_permissions,
)
from pathlib import Path
from django.db import transaction

from volatility3.plugins.linux.pslist import PsList
from volatility3.plugins.linux.proc import Maps
from volatility3.framework.plugins import construct_plugin
from volatility3.plugins.windows.dumpfiles import DumpFiles
from .plugins.windows.volweb_main import VolWebMain as VolWebMainW
from .plugins.windows.volweb_misc import VolWebMisc as VolWebMiscW
from .plugins.linux.volweb_main import VolWebMain as VolWebMainL
from .plugins.linux.volweb_misc import VolWebMisc as VolWebMiscL
from volatility3.framework import contexts, automagic
from volatility3 import framework
import volatility3.plugins
from volatility3.framework.symbols.linux import extensions as linux_ext
import yara
import tempfile

volatility3.framework.require_interface_version(2, 0, 0)
logger = logging.getLogger(__name__)


def _match_yara_braces(source, start):
    """
    Given the index of an opening ``{`` in ``source``, return the index just
    past its matching ``}``. String literals and comments are skipped so that
    braces appearing inside them are ignored. Hex strings and regex
    quantifiers ({n,m}) keep their braces balanced, so plain depth counting
    locates the real end of a rule body.
    """
    depth = 0
    k, n = start, len(source)
    while k < n:
        ch = source[k]
        if ch == '"':
            k += 1
            while k < n:
                if source[k] == '\\':
                    k += 2
                    continue
                if source[k] == '"':
                    k += 1
                    break
                k += 1
            continue
        if source.startswith("//", k):
            nl = source.find("\n", k)
            k = n if nl == -1 else nl
            continue
        if source.startswith("/*", k):
            end = source.find("*/", k)
            k = n if end == -1 else end + 2
            continue
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return k + 1
        k += 1
    return n


def _dedupe_yara_rules(source):
    """
    Drop duplicate top-level rule definitions (keeping the first of each
    identifier) and collapse duplicate import/include statements, so a
    duplicated identifier doesn't make yara.compile abort the whole scan.

    Returns ``(deduped_source, dropped_identifiers)``.
    """
    imports = []
    seen_imports = set()
    rules_out = []
    seen_rules = set()
    dropped = []

    rule_decl = re.compile(r'((?:(?:private|global)\s+)*)rule\s+([A-Za-z_]\w*)')
    import_decl = re.compile(r'(import|include)\s+("[^"]*")')

    i, n = 0, len(source)
    while i < n:
        ch = source[i]

        if ch.isspace():
            i += 1
            continue
        if source.startswith("//", i):
            nl = source.find("\n", i)
            i = n if nl == -1 else nl
            continue
        if source.startswith("/*", i):
            end = source.find("*/", i)
            i = n if end == -1 else end + 2
            continue

        m = import_decl.match(source, i)
        if m:
            stmt = f"{m.group(1)} {m.group(2)}"
            if stmt not in seen_imports:
                seen_imports.add(stmt)
                imports.append(stmt)
            i = m.end()
            continue

        m = rule_decl.match(source, i)
        if m:
            identifier = m.group(2)
            brace_start = source.find("{", m.end())
            if brace_start == -1:
                break  # malformed input — stop parsing defensively
            end = _match_yara_braces(source, brace_start)
            rule_text = source[i:end].strip()
            if identifier in seen_rules:
                dropped.append(identifier)
            else:
                seen_rules.add(identifier)
                rules_out.append(rule_text)
            i = end
            continue

        # Unrecognised token — advance one char to stay robust.
        i += 1

    parts = []
    if imports:
        parts.append("\n".join(imports))
    parts.extend(rules_out)
    return ("\n\n".join(parts) + "\n", dropped)


class VolatilityEngine:
    """
    The Volatility3 Engine is a modular class to enable the execution multiple volatility3 plugins.
    It is used by VolWeb when a user just uploaded a memory image for a given Evidence
    """

    def __init__(self, obj) -> None:
        self.obj: object = obj

        if isinstance(obj, Evidence):
            self.evidence_data = {
                "bucket": obj.url,
                "output_path": f"media/{obj.id}/",
            }

        elif isinstance(obj, YaraRule):
            self.yararule_data = {
                "bucket": obj.url,
                "output_path": f"yararules/{obj.id}/",
            }

        elif isinstance(obj, YaraRuleSet):
            self.ruleset_data = {
                "output_path": f"yararulesets/{obj.id}/",
            }

        else:
            raise TypeError(f"Unsupported object type: {type(obj)}")

        self.base_config_path = "plugins"
        self._modules_loaded = False
        self._load_core_modules()

    def _purge_previous_run(self) -> None:
        """
        Remove all VolWeb-generated artefacts linked to this Evidence
        (database rows *and* exported files) so the forthcoming analysis
        starts from a clean slate.
        """
        with transaction.atomic():
            VolatilityPlugin.objects.filter(
                evidence=self.obj
            ).delete()
            EnrichedProcess.objects.filter(
                evidence=self.obj
            ).delete()
        artefact_dir = Path(f"media/{self.obj.id}")
        if artefact_dir.exists():
            shutil.rmtree(artefact_dir, ignore_errors=True)
        artefact_dir.mkdir(parents=True, exist_ok=True)

    def _purge_selected_plugins(self, plugin_names) -> None:
        """
        Remove only the specified plugin records from the database.
        Keeps successful plugins intact. Also rebuilds EnrichedProcess data.
        """
        with transaction.atomic():
            VolatilityPlugin.objects.filter(
                evidence=self.obj,
                name__in=plugin_names,
            ).delete()
            EnrichedProcess.objects.filter(
                evidence=self.obj
            ).delete()
        os.makedirs(f"media/{self.obj.id}", exist_ok=True)

    def _get_successful_plugin_names(self) -> list:
        """
        Returns the list of plugin names that completed successfully (results=True)
        for this evidence.
        """
        return list(
            VolatilityPlugin.objects.filter(
                evidence=self.obj,
                results=True,
            ).values_list("name", flat=True)
        )


    def _load_core_modules(self):
        if self._modules_loaded:
            return


        framework.import_files(volatility3.plugins, True)   # plugins (all OSes)
        framework.import_files(linux_ext, True)             # linux symbol ext.
        self._modules_loaded = True


    def build_context(self, plugin):
        self.plugin, self.metadata = plugin.popitem()
        
        if hasattr(self, 'context') and self.context:
            previous_config = dict(self.context.config)
            logger.info(f"Previous context config: {previous_config}")
        
        self.context = contexts.Context()
        available_automagics = automagic.available(self.context)
        
        self.automagics = automagic.choose_automagic(available_automagics, self.plugin)
        
        self.context.config["automagic.LayerStacker.single_location"] = (
            self.evidence_data["bucket"]
        )
        
        self.context.config["automagic.LayerStacker.stackers"] = (
            automagic.stacker.choose_os_stackers(self.plugin)
        )
        
        self.context.config["VolWeb.Evidence"] = self.obj.id
        
        if "yarascan" in str(self.plugin).lower():
            logger.info(f"Building context for YaraScan plugin")
            logger.info(f"Plugin class: {self.plugin}")
            logger.info(f"Evidence bucket: {self.evidence_data['bucket']}")
            logger.info(f"Available automagics: {[a.__class__.__name__ for a in available_automagics]}")
        
        logger.debug(f"Context config: {self.context.config}")


    def construct_plugin(self):
        """
        This Method can be used to execute any plugins this will:
            - Create a new context
            - Choose the automagics
            - Construct the plugin
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
            result = DjangoRenderer(self.obj.id, self.metadata).render(
                constructed.run()
            )
            return result
        return None

    def _collect_grid(self, plugin, column=None):
        """
        Run a plugin and collect rows in-memory (no DB persistence).
        Returns a list of the values of ``column`` (or full value tuples).
        """
        self.build_context(plugin)
        constructed = self.construct_plugin()
        if not constructed:
            return []
        grid = constructed.run()
        col_names = [c.name for c in grid.columns]
        idx = col_names.index(column) if column in col_names else None
        rows = []

        def _visit(node, acc):
            try:
                values = list(node.values)
                rows.append(values[idx] if idx is not None else values)
            except Exception:
                pass
            return acc

        if not grid.populated:
            grid.populate(_visit, None)
        else:
            grid.visit(node=None, function=_visit, initial_accumulator=None)
        return rows

    def detect_linux_banner(self):
        """Scan the image for the Linux kernel banner; return it or None."""
        import volatility3.plugins.banners

        banners = self._collect_grid(
            {volatility3.plugins.banners.Banners: {"name": "banners"}}, column="Banner"
        )
        banners = [str(b).strip().strip("\x00").strip() for b in banners if b]
        for banner in banners:
            if "Linux version" in banner:
                return banner
        return banners[0] if banners else None

    def verify_linux_symbols(self):
        """Return True if Linux symbols resolve for this image (runs linux.pslist)."""
        try:
            rows = self._collect_grid({PsList: {"name": "verify"}})
            return len(rows) > 0
        except UnsatisfiedException:
            return False
        except Exception as e:
            logger.warning(f"Linux symbol verification failed: {e}")
            return False

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
            VolatilityPlugin.objects.update_or_create(
                name="volatility3.plugins.timeliner.TimelinerGraph",
                icon="None",
                description="None",
                evidence=self.obj,
                artefacts=graph,
                category="Timeline",
                display="False",
                results=True,
            )
        return result

    def start_selective_extraction(self, selected_plugins=None, pid_filter=None, skip_completed=False, plugin_timeout=None):
        """
        Run only the selected plugins instead of all plugins.
        selected_plugins: list of plugin name strings
        pid_filter: optional PID to filter process-based plugins
        skip_completed: if True, skip plugins that already have results=True
        plugin_timeout: optional per-plugin timeout in seconds (None = no timeout)
        """
        try:
            if skip_completed:
                successful = self._get_successful_plugin_names()
                original_count = len(selected_plugins)
                selected_plugins = [p for p in selected_plugins if p not in successful]
                logger.info(f"Smart selective: skipping {original_count - len(selected_plugins)} successful plugins")
                if not selected_plugins:
                    logger.info("All selected plugins already completed successfully, nothing to re-run")
                    return
                self._purge_selected_plugins(selected_plugins)
            else:
                self._purge_previous_run()
            logger.info(f"Starting selective extraction with {len(selected_plugins)} plugins")
            self.obj.status = 0
            os.makedirs(f"media/{self.obj.id}", exist_ok=True)

            # Load plugin registries to separate main vs misc
            with open("volatility_engine/volweb_plugins.json", "r") as f:
                all_main = json.load(f).get("plugins", {}).get(self.obj.os, {})
            with open("volatility_engine/volweb_misc.json", "r") as f:
                all_misc = json.load(f).get("plugins", {}).get(self.obj.os, {})

            main_selected = [p for p in selected_plugins if p in all_main]
            misc_selected = [p for p in selected_plugins if p in all_misc]

            if self.obj.os == "windows":
                if main_selected:
                    self._run_selective_wrapper(VolWebMainW, main_selected, pid_filter, plugin_timeout)
                if misc_selected:
                    self._run_selective_wrapper(VolWebMiscW, misc_selected, pid_filter, plugin_timeout)
                self.construct_windows_explorer()
            else:
                if main_selected:
                    self._run_selective_wrapper(VolWebMainL, main_selected, pid_filter, plugin_timeout)
                if misc_selected:
                    self._run_selective_wrapper(VolWebMiscL, misc_selected, pid_filter, plugin_timeout)
                self.construct_linux_explorer()

        except UnsatisfiedException as e:
            self.obj.status = -1
            self.obj.save(update_fields=["status"])
            logger.warning(f"Unsatisfied requirements: {str(e)}")
        except Exception as e:
            self.obj.status = -1
            self.obj.save(update_fields=["status"])
            logger.error(f"Unknown error in selective extraction: {str(e)}")
            logger.error(traceback.format_exc())

    def _run_selective_wrapper(self, wrapper_class, selected_plugins, pid_filter=None, plugin_timeout=None):
        """
        Run a wrapper plugin with a filtered plugin list.
        Passes the selected plugin list through the Volatility3 context config.
        """
        plugin_entry = {
            wrapper_class: {
                "icon": "None",
                "description": f"VolWeb selective execution of {len(selected_plugins)} plugins",
                "category": "Other",
                "display": "False",
                "name": "VolWebSelective",
            }
        }

        self.build_context(plugin_entry)

        # Pass selected plugins via context config
        self.context.config["VolWeb.SelectedPlugins"] = json.dumps(selected_plugins)

        # Pass optional PID filter
        if pid_filter is not None:
            self.context.config["VolWeb.PidFilter"] = int(pid_filter)

        # Pass optional per-plugin timeout
        if plugin_timeout is not None:
            self.context.config["VolWeb.PluginTimeout"] = int(plugin_timeout)

        builted_plugin = self.construct_plugin()
        self.run_plugin(builted_plugin)
        fix_permissions(self.evidence_data["output_path"])

    def dump_process(self, pid):
        logger.info(f"Trying to dump PID {pid}")
        if self.obj.os == "windows":
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
        fix_permissions(f"media/{self.obj.id}")
        return result

    def dump_process_maps(self, pid):
        logger.info(f"Trying to dump PID {pid}")
        if self.obj.os == "windows":
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
        fix_permissions(f"media/{self.obj.id}")
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

    def dump_file_windows(self, offset):
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
        self.context.config["plugins.DumpFiles.virtaddr"] = [int(offset)]
        builted_plugin = self.construct_plugin()
        try:
            result = self.run_plugin(builted_plugin)
            if not result:
                del self.context.config["plugins.DumpFiles.virtaddr"]
                self.context.config["plugins.DumpFiles.physaddr"] = [int(offset)]
                result = self.run_plugin(builted_plugin)

            fix_permissions(f"media/{self.obj.id}")
            return result
        except Exception as e:
            logger.error(e)
            return None


    def dump_file_linux(self, offset):
        dumpfiles_plugin = {
            DumpFiles: {
                "icon": "N/A",
                "description": "N/A",
                "category": "Processes",
                "display": "False",
                "name": f"volatility3.plugins.linux.pagecache.Inode.{offset}",
            }
        }
        self.build_context(dumpfiles_plugin)
        self.context.config["plugins.DumpFiles.virtaddr"] = [int(offset)]
        builted_plugin = self.construct_plugin()
        try:
            result = self.run_plugin(builted_plugin)
            fix_permissions(f"media/{self.evidence.id}")
            if not result:
                del self.context.config["plugins.DumpFiles.virtaddr"]
                self.context.config["plugins.DumpFiles.physaddr"] = [int(offset)]
                result = self.run_plugin(builted_plugin)

            fix_permissions(f"media/{self.obj.id}")
            return result
        except Exception as e:
            logger.error(e)
            return None



    def construct_windows_explorer(self):
        # Get all VolatilityPlugin objects linked to this evidence
        plugins = VolatilityPlugin.objects.filter(evidence=self.obj)

        # Get the pslist plugin's output, which contains the list of processes
        try:
            pslist_plugin = VolatilityPlugin.objects.get(
                evidence=self.obj, name="volatility3.plugins.windows.pslist.PsList"
            )
        except VolatilityPlugin.DoesNotExist:
            logger.error("pslist plugin not found for this evidence")
            return

        pslist_artefacts = (
            pslist_plugin.artefacts
        )  # This should be a list of process dicts

        # Iterate over each process in pslist
        for process in pslist_artefacts:
            pid = process.get("PID") or process.get("Process ID")
            if pid is None:
                continue  # Skip if no PID
            pid = int(pid)

            # Initialize enriched process data with pslist data
            enriched_process_data = {"pslist": process}

            # Iterate over other plugins linked to the same evidence
            for plugin in plugins.exclude(id=pslist_plugin.id):
                artefacts = plugin.artefacts
                if not artefacts:
                    continue
                # Check if the PID matches in the plugin's artefacts
                for artefact in artefacts:
                    if not isinstance(artefact, list):
                        plugin_pid = artefact.get("PID") or artefact.get("Process ID")
                        try:
                            if plugin_pid and int(plugin_pid) == pid:
                                # Ensure enriched process data contains an array of artefacts
                                if plugin.name not in enriched_process_data:
                                    enriched_process_data[plugin.name] = []
                                # Append the artefact to the array
                                enriched_process_data[plugin.name].append(artefact)
                        except:
                            pass


            # Save the enriched process data into the EnrichedProcess model
            EnrichedProcess.objects.update_or_create(
                evidence=self.obj,
                pid=pid,
                defaults={"data": enriched_process_data},
            )


    def construct_linux_explorer(self):
        # Get all VolatilityPlugin objects linked to this evidence
        plugins = VolatilityPlugin.objects.filter(evidence=self.obj)

        # Get the pslist plugin's output, which contains the list of processes
        try:
            pslist_plugin = VolatilityPlugin.objects.get(
                evidence=self.obj, name="volatility3.plugins.linux.pslist.PsList"
            )
        except VolatilityPlugin.DoesNotExist:
            logger.error("pslist plugin not found for this evidence")
            return

        pslist_artefacts = (
            pslist_plugin.artefacts
        )  # This should be a list of process dicts

        # Iterate over each process in pslist
        for process in pslist_artefacts:
            pid = process.get("PID") or process.get("Process ID")
            if pid is None:
                continue  # Skip if no PID
            pid = int(pid)

            # Initialize enriched process data with pslist data
            enriched_process_data = {"pslist": process}

            # Iterate over other plugins linked to the same evidence
            for plugin in plugins.exclude(id=pslist_plugin.id):
                artefacts = plugin.artefacts
                if not artefacts:
                    continue
                # Check if the PID matches in the plugin's artefacts
                for artefact in artefacts:
                    if not isinstance(artefact, list):
                        plugin_pid = artefact.get("PID") or artefact.get("Process ID") or artefact.get("Pid")
                        try:
                            if plugin_pid and int(plugin_pid) == pid:
                                # Ensure enriched process data contains an array of artefacts
                                if plugin.name not in enriched_process_data:
                                    enriched_process_data[plugin.name] = []
                                # Append the artefact to the array
                                enriched_process_data[plugin.name].append(artefact)
                        except:
                            pass

            # Save the enriched process data into the EnrichedProcess model
            EnrichedProcess.objects.update_or_create(
                evidence=self.obj,
                pid=pid,
                defaults={"data": enriched_process_data},
            )
    
    def start_yararule_validation(self):
        try:
            logger.info(f"Validating YARA rule: {self.obj.name}")
            
            # Check for empty rule content
            if not self.obj.rule_content or not self.obj.rule_content.strip():
                logger.error(f"YARA rule '{self.obj.name}' has no content")
                self.obj.status = -1  # Empty content error
                self.obj.save()
                return False
                
            # Try to compile the rule
            yara.compile(source=self.obj.rule_content)
            
            # Success case
            self.obj.status = 100
            self.obj.save()
            logger.info(f"YARA rule '{self.obj.name}' is valid")
            return True

        except yara.SyntaxError as e:
            # Syntax errors in YARA rule
            logger.error(f"Syntax error in rule '{self.obj.name}': {e}")
            self.obj.status = -2  # Specific syntax error code
            self.obj.save()
            return False

        except yara.Error as e:
            # Other YARA-specific errors
            logger.error(f"YARA compilation error in rule '{self.obj.name}': {e}")
            self.obj.status = -3  # General YARA error code
            self.obj.save()
            return False

        except Exception as e:
            # Generic/unexpected errors
            logger.error(f"Unexpected error validating rule '{self.obj.name}': {e}")
            logger.error(traceback.format_exc())
            self.obj.status = -4  # System/unknown error code
            self.obj.save()
            return False

    def start_ruleset_validation(self, skip_rule_validation=False):
        """
        Compile all active YARA rules in the ruleset.
        skip_rule_validation: if True, skip per-rule validation (e.g. after deletion,
                              remaining rules are already compiled — no need to revalidate).
        Revised status codes:
            100 -> Success
            -1  -> No active rules
            -2  -> No valid rules
            -3  -> General error
        """
        try:
            logger.info(f"Starting compilation for ruleset: {self.obj.name}")

            # Fetch active rules only once to avoid stale data
            with transaction.atomic():
                active_rules = list(YaraRule.objects.filter(
                    linked_yararuleset=self.obj,
                    is_active=True
                ).select_for_update())

            logger.info(f"Found {len(active_rules)} active rules for ruleset '{self.obj.name}'")
            

            if not active_rules:
                logger.info(f"No active rules found in ruleset '{self.obj.name}'")
                self.obj.compiled_rules = None
                self.obj.status = -1
                self.obj.save()
                return self.obj.status

            if not skip_rule_validation:
                # Validate only rules that need compilation
                rules_to_validate = [r for r in active_rules if r.status != 100]
                for rule in rules_to_validate:
                    try:
                        rule_engine = VolatilityEngine(rule)
                        rule_engine.start_yararule_validation()
                        rule.refresh_from_db()
                    except Exception as e:
                        logger.error(f"Failed to validate rule '{rule.name}': {e}")

            # Collect only successfully validated rules
            valid_rules = [r for r in active_rules if r.status == 100]
            valid_rules_count = len(valid_rules)
            
            if not valid_rules:
                logger.info(f"No valid compiled rules found in ruleset '{self.obj.name}'")
                self.obj.compiled_rules = None
                self.obj.status = -2
                self.obj.save()
                return self.obj.status

            logger.info(f"Compiling {valid_rules_count} valid rules into ruleset...")
            
            try:
                # Create rules dictionary for compilation
                rules_dict = {}
                for rule in valid_rules:
                    rules_dict[f"rule_{rule.id}"] = rule.rule_content

                compiled_rules = yara.compile(sources=rules_dict)
                
                # Serialize compiled rules
                import io
                binary_data = io.BytesIO()
                compiled_rules.save(file=binary_data)
                self.obj.compiled_rules = binary_data.getvalue()
                
                # Final success status
                self.obj.status = 100
                self.obj.save()
                
                logger.info(f"Successfully compiled ruleset '{self.obj.name}'")
                return self.obj.status
                
            except yara.Error as e:
                logger.error(f"Ruleset compilation failed: {str(e)}")
                self.obj.status = -3
                self.obj.save()
                return self.obj.status

        except Exception as e:
            logger.error(f"Ruleset validation failed: {str(e)}")
            self.obj.status = -3
            self.obj.save()
            return self.obj.status
        
    def run_yara_scan(self, yara_ruleset=None, yara_rules=None, yara_rulesets=None, scan_scope="vad"):
        """
        Run YARA scan on evidence with selected ruleset(s) or rules.

        scan_scope:
            - "vad"    -> scan process memory via VadYaraScan (default).
                          Best for malware/ransomware artefacts in user space.
            - "kernel" -> scan the primary (kernel) layer via plain YaraScan.
                          Use for rootkits or kernel-mode threats.
        """
        from yararules.models import YaraRule
        import traceback
        import os
        import time
        from datetime import datetime
        
        try:
            logger.info(f"Starting YARA scan on evidence '{self.obj.name}'")
            
            # === PREPARATION PHASE ===
            combined_rules = ""
            
            # Determine scan description based on what was passed
            scan_description_parts = []
            active_rules = YaraRule.objects.none()  # Start with empty QuerySet
            
            if yara_rulesets:
                # Multiple rulesets - NEW functionality
                logger.info(f"Processing {len(yara_rulesets)} rulesets")
                ruleset_names = []
                
                for ruleset in yara_rulesets:
                    if not ruleset.compiled_rules:
                        logger.warning(f"Ruleset '{ruleset.name}' has no compiled rules, skipping")
                        continue
                    
                    ruleset_names.append(ruleset.name)
                    
                    # Get rules from this ruleset
                    ruleset_rules = YaraRule.objects.filter(
                        linked_yararuleset=ruleset,
                        is_active=True,
                        status=100
                    )
                    
                    # Combine with other active rules
                    active_rules = active_rules.union(ruleset_rules)
                    
                    # Add rule contents
                    for rule in ruleset_rules:
                        combined_rules += rule.rule_content + "\n\n"
                
                # Create description for multiple rulesets
                if len(ruleset_names) <= 2:
                    scan_description_parts.append(f"rulesets: {', '.join(ruleset_names)}")
                else:
                    scan_description_parts.append(f"rulesets: {', '.join(ruleset_names[:2])}, +{len(ruleset_names) - 2} more")
                    
            elif yara_ruleset:
                # Single ruleset - existing functionality
                if not yara_ruleset.compiled_rules:
                    logger.error(f"Ruleset '{yara_ruleset.name}' has no compiled rules")
                    return None

                active_rules = YaraRule.objects.filter(
                    linked_yararuleset=yara_ruleset,
                    is_active=True,
                    status=100
                )
                
                # Combine rule contents from the ruleset
                for rule in active_rules:
                    combined_rules += rule.rule_content + "\n\n"
                    
                scan_description_parts.append(f"ruleset: {yara_ruleset.name}")

            elif yara_rules:
                # Individual rule IDs
                active_rules = YaraRule.objects.filter(
                    id__in=yara_rules,
                    is_active=True,
                    status=100
                )
                
                # Log the rules found
                logger.info(f"Found {active_rules.count()} active rules from IDs: {yara_rules}")
                
                # Combine rule contents from individual rules
                for rule in active_rules:
                    logger.info(f"Adding rule '{rule.name}' to scan")
                    combined_rules += rule.rule_content + "\n\n"
                    
                rule_count = len(yara_rules) if isinstance(yara_rules, list) else 1
                scan_description_parts.append(f"{rule_count} individual rule{'s' if rule_count > 1 else ''}")

            else:
                # Using all active rules
                active_rules = YaraRule.objects.filter(is_active=True, status=100)
                
                if not active_rules.exists():
                    logger.warning("No active YARA rules found in database")
                    return None
                
                # Combine all rule contents
                for rule in active_rules:
                    combined_rules += rule.rule_content + "\n\n"
                    
                scan_description_parts.append("All Active Rules")

            # Check if we have any rules to scan with
            if not combined_rules.strip():  
                logger.warning("No active YARA rules found for scanning")
                return None
            
            logger.info(f"Combined {active_rules.count()} rules for scanning")

            # Drop duplicate identifiers so a collision doesn't abort the scan.
            combined_rules, dropped_rules = _dedupe_yara_rules(combined_rules)
            if dropped_rules:
                logger.warning(
                    f"Dropped {len(dropped_rules)} duplicate rule identifier(s) "
                    f"before compilation: {', '.join(sorted(set(dropped_rules)))}"
                )

            logger.debug(f"Combined rules content length: {len(combined_rules)} characters")
                            
            # === FILE CREATION PHASE ===
            # Create temporary file with the combined rules
            
            # Use the evidence output directory which we know is accessible
            output_dir = self.evidence_data["output_path"]
            os.makedirs(output_dir, exist_ok=True)
            
            temp_file_name = f"yara_rules_{int(time.time())}.yara"
            temp_file_path = os.path.join(output_dir, temp_file_name)
            
            # Write the file
            with open(temp_file_path, 'w') as f:
                f.write(combined_rules)
                
            # Verify that the file was created
            if not os.path.exists(temp_file_path):
                logger.error(f"Failed to create YARA file at: {temp_file_path}")
                return None
                
            logger.info(f"YARA file created: {temp_file_path} ({os.path.getsize(temp_file_path)} bytes)")
            
            # === EXECUTION PHASE ===
            logger.info("Executing YARA scan...")
            
            scan_id = "latest"
            
            # Create description with current timestamp
            formatted_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            scan_description = f"YARA scan using {' + '.join(scan_description_parts)} - processing at {formatted_timestamp}"
            
            # "vad" -> per-process VadYaraScan (user space); "kernel" -> generic
            # YaraScan on the primary layer (kernel space).
            target_os = getattr(self.obj, "os", "windows")
            normalized_scope = (scan_scope or "vad").lower()
            if normalized_scope == "kernel":
                yarascan_cls = volatility3.plugins.yarascan.YaraScan
                plugin_config_prefix = "plugins.YaraScan"
            else:
                if target_os == "linux":
                    import volatility3.plugins.linux.vmayarascan as _vad_mod
                    yarascan_cls = _vad_mod.VmaYaraScan
                    plugin_config_prefix = "plugins.VmaYaraScan"
                else:
                    import volatility3.plugins.windows.vadyarascan as _vad_mod
                    yarascan_cls = _vad_mod.VadYaraScan
                    plugin_config_prefix = "plugins.VadYaraScan"

            yara_plugin = {
                yarascan_cls: {
                    "icon": "🔍",
                    "description": scan_description,
                    "category": "Malware",
                    "display": "False",
                    "name": f"volatility3.plugins.yarascan.{scan_id}",
                }
            }

            # Build context and configure plugin
            self.build_context(yara_plugin)

            # Configure both the chosen plugin and the underlying YaraScan it delegates to.
            file_url = f"file://{os.path.abspath(temp_file_path)}"
            for prefix in (plugin_config_prefix, "plugins.YaraScan"):
                self.context.config[f"{prefix}.yara_file"] = file_url

            logger.info(f"YARA plugin selected: {yarascan_cls.__module__}.{yarascan_cls.__name__}")
            logger.info(f"Context config after YARA file: {self.context.config.get(f'{plugin_config_prefix}.yara_file')}")
            logger.info(f"Layer stacker location: {self.context.config.get('automagic.LayerStacker.single_location')}")

            # Build and run the plugin
            builted_plugin = self.construct_plugin()

            if not builted_plugin:
                logger.error("Failed to construct VadYaraScan plugin")

                # Retry with the absolute path (some builds reject the file:// form).
                logger.info("Retrying with absolute path...")
                abs_path = os.path.abspath(temp_file_path)
                for prefix in (plugin_config_prefix, "plugins.YaraScan"):
                    self.context.config[f"{prefix}.yara_file"] = abs_path
                builted_plugin = self.construct_plugin()

                if not builted_plugin:
                    # Last attempt: relative path
                    logger.info("Retrying with relative path...")
                    for prefix in (plugin_config_prefix, "plugins.YaraScan"):
                        self.context.config[f"{prefix}.yara_file"] = temp_file_name
                    builted_plugin = self.construct_plugin()

                if not builted_plugin:
                    logger.error("All attempts to construct VadYaraScan plugin failed")
                    return None

            # Stream each match directly to a JSONL file — no in-memory accumulation.
            # This prevents OOM crashes when broad rules (domain/url/IP) produce
            # millions of matches on a large memory image.
            results_file_path = os.path.join(output_dir, "yarascan_results.jsonl")

            # Delete the old scan entry + its JSONL file NOW, before truncating the file.
            # If we did this after streaming, a mid-scan SIGTERM would leave the old DB
            # entry pointing to a truncated/partial file.
            old_scans = VolatilityPlugin.objects.filter(
                evidence=self.obj,
                name=f"volatility3.plugins.yarascan.{scan_id}"
            )
            for old_scan in old_scans:
                old_artefacts = old_scan.artefacts or {}
                if isinstance(old_artefacts, dict) and old_artefacts.get("streaming"):
                    old_file = old_artefacts.get("file", "")
                    if old_file and os.path.exists(old_file):
                        try:
                            os.unlink(old_file)
                        except Exception:
                            pass
            old_scans.delete()

            type_renderers = DjangoRenderer._type_renderers
            match_count = [0]
            grid = builted_plugin.run()

            from volatility3.framework.interfaces.renderers import BaseAbsentValue as _BaseAbsentValue
            logger.info(f"Streaming YARA results to {results_file_path}")

            with open(results_file_path, 'w', buffering=8192) as _results_file:
                def _stream_visitor(node, accumulator):
                    node_dict = {}
                    for _ci in range(len(grid.columns)):
                        _col = grid.columns[_ci]
                        _renderer = type_renderers.get(_col.type, type_renderers["default"])
                        _data = _renderer(list(node.values)[_ci])
                        if isinstance(_data, _BaseAbsentValue):
                            _data = None
                        node_dict[_col.name] = _data
                    _results_file.write(json.dumps(node_dict) + "\n")
                    match_count[0] += 1
                    return accumulator

                if not grid.populated:
                    grid.populate(_stream_visitor, ({}, []))
                else:
                    grid.visit(node=None, function=_stream_visitor, initial_accumulator=({}, []))

            total_matches = match_count[0]
            logger.info(f"YARA scan found {total_matches} matches, streamed to {results_file_path}")
            result = total_matches > 0
            
            # Fix permissions
            fix_permissions(self.evidence_data["output_path"])
            
            # === SAVE RESULTS TO DATABASE ===
            # Store file reference + count instead of the full artefacts list
            has_results = total_matches > 0
            artefacts = {
                "streaming": True,
                "file": results_file_path,
                "count": total_matches,
            }

            # Update description with actual results count
            final_description = f"YARA scan using {' + '.join(scan_description_parts)} - {total_matches} matches found at {formatted_timestamp}"

            VolatilityPlugin.objects.create(
                name=f"volatility3.plugins.yarascan.{scan_id}",
                evidence=self.obj,
                icon="🔍",
                description=final_description,
                artefacts=artefacts,
                category="Malware",
                display="False",
                results=has_results,
            )
            
            # === CLEANUP OLD SCANS ===
            
            logger.info(f"YARA scan results saved to database as latest scan")
            
            logger.info(f"YARA scan completed for evidence '{self.obj.name}' - Found {total_matches} matches")
            return result
            
        except Exception as e:
            logger.error(f"Failed to run YARA scan on evidence '{self.obj.name}': {str(e)}")
            logger.error(traceback.format_exc())
            # Propagate so the calling task reports an error, not a fake success.
            raise
            
        finally:
            # Cleanup of temporary file
            if 'temp_file_path' in locals() and os.path.exists(temp_file_path):
                try:
                    os.unlink(temp_file_path)
                    logger.info(f"Cleaned up temporary YARA file: {temp_file_path}")
                except Exception as cleanup_error:
                    logger.warning(f"Failed to cleanup temp file: {cleanup_error}")

