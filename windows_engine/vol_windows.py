import logging, json
import volatility3
from volatility3.framework.plugins import construct_plugin
from volatility3.framework import automagic, contexts
from evidences.models import Evidence
from windows_engine.models import *
from volatility3 import plugins
from django.apps import apps
from VolWeb.voltools import *
from volatility3.framework.exceptions import *
from volatility3.cli import MuteProgress


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def build_context(instance, context, base_config_path, plugin, output_path):
    """This function is used to buid the context and construct each plugin
    Return : The contructed plugin.
    """
    available_automagics = automagic.available(context)
    automagics = automagic.choose_automagic(available_automagics, plugin)
    context.config[
        "automagic.LayerStacker.stackers"
    ] = automagic.stacker.choose_os_stackers(plugin)
    context.config["automagic.LayerStacker.single_location"] = (
        "s3://"
        + str(instance.dump_linked_case.case_bucket_id)
        + "/"
        + instance.dump_name
    )
    constructed = construct_plugin(
        context,
        automagics,
        plugin,
        base_config_path,
        MuteProgress(),
        file_handler(output_path),
    )
    return constructed


def pslist_dump(instance, pid):
    """Dump the process requested by the user using the pslist plugin"""
    volatility3.framework.require_interface_version(2, 0, 0)
    failures = volatility3.framework.import_files(plugins, True)
    if failures:
        logger.info(f"Some volatility3 plugin couldn't be loaded : {failures}")
    else:
        logger.info(f"Plugins are loaded without failure")
    plugin_list = volatility3.framework.list_plugins()
    base_config_path = "plugins"
    context = contexts.Context()
    context.config["plugins.PsList.pid"] = [
        pid,
    ]
    context.config["plugins.PsList.dump"] = True
    output_path = "./media/"
    constructed = build_context(
        instance,
        context,
        base_config_path,
        plugin_list["windows.pslist.PsList"],
        output_path,
    )
    result = DictRenderer().render(constructed.run())
    artefact = {x.translate({32: None}): y for x, y in result[0].items()}
    return artefact["Fileoutput"]


def memmap_dump(instance, pid):
    """Dump the process requested by the user using the memmap plugin"""
    volatility3.framework.require_interface_version(2, 0, 0)
    failures = volatility3.framework.import_files(plugins, True)
    if failures:
        logger.info(f"Some volatility3 plugin couldn't be loaded : {failures}")
    else:
        logger.info(f"Plugins are loaded without failure")
    plugin_list = volatility3.framework.list_plugins()
    base_config_path = "plugins"
    context = contexts.Context()
    context.config["plugins.Memmap.pid"] = int(pid)
    context.config["plugins.Memmap.dump"] = True
    output_path = "./media/"
    constructed = build_context(
        instance,
        context,
        base_config_path,
        plugin_list["windows.memmap.Memmap"],
        output_path,
    )
    result = DictRenderer().render(constructed.run())
    artefact = {x.translate({32: None}): y for x, y in result[0].items()}
    return artefact["Fileoutput"]


def get_handles(instance, pid):
    """Compute Handles for a specific PID"""
    volatility3.framework.require_interface_version(2, 0, 0)
    failures = volatility3.framework.import_files(plugins, True)
    if failures:
        logger.info(f"Some volatility3 plugin couldn't be loaded : {failures}")
    else:
        logger.info(f"Plugins are loaded without failure")
    plugin_list = volatility3.framework.list_plugins()
    base_config_path = "plugins"
    context = contexts.Context()
    context.config["plugins.Handles.pid"] = [int(pid)]
    try:
        constructed = build_context(
            instance,
            context,
            base_config_path,
            plugin_list["windows.handles.Handles"],
            output_path=None,
        )
        result = DictRenderer().render(constructed.run())
        for artefact in result:
            artefact = {x.translate({32: None}): y for x, y in artefact.items()}
            del artefact["__children"]
            Handles(evidence=instance, **artefact).save()
        return instance
    except:
        return None


def dump_file(instance, offset, output_path):
    """Dump the file requested by the user"""
    volatility3.framework.require_interface_version(2, 0, 0)
    failures = volatility3.framework.import_files(plugins, True)
    if failures:
        logger.info(f"Some volatility3 plugin couldn't be loaded : {failures}")
    else:
        logger.info(f"Plugins are loaded without failure")
    plugin_list = volatility3.framework.list_plugins()
    base_config_path = "plugins"
    context = contexts.Context()
    context.config["plugins.DumpFiles.virtaddr"] = int(offset)
    try:
        constructed = build_context(
            instance,
            context,
            base_config_path,
            plugin_list["windows.dumpfiles.DumpFiles"],
            output_path,
        )
        result = DictRenderer().render(constructed.run())
        if len(result) < 1:
            del context.config["plugins.DumpFiles.virtaddr"]
            context.config["plugins.DumpFiles.physaddr"] = int(offset)
            constructed = build_context(
                instance,
                context,
                base_config_path,
                plugin_list["windows.dumpfiles.DumpFiles"],
                output_path,
            )
        result = DictRenderer().render(constructed.run())
        for artefact in result:
            artefact = {x.translate({32: None}): y for x, y in artefact.items()}
        return result
    except:
        return None


def fill_userassist(list, dump_id):
    for artefact in list:
        artefact = {x.translate({32: None}): y for x, y in artefact.items()}
        apps.get_model("windows_engine", "UserAssist")(
            evidence=dump_id,
            HiveOffset=artefact["HiveOffset"],
            HiveName=artefact["HiveName"],
            Path=artefact["Path"],
            LastWriteTime=artefact["LastWriteTime"],
            Type=artefact["Type"],
            Name=artefact["Name"],
            ID=artefact["ID"],
            Count=artefact["Count"],
            FocusCount=artefact["FocusCount"],
            TimeFocused=artefact["TimeFocused"],
            LastUpdated=artefact["LastUpdated"],
            RawData=artefact["RawData"],
        ).save()
        if artefact["__children"]:
            fill_userassist(artefact["__children"], dump_id)


def rename_pstree(node):
    if len(node["__children"]) == 0:
        node["children"] = node["__children"]
        node["name"] = node["ImageFileName"]
        del node["__children"]
        del node["ImageFileName"]
    else:
        node["children"] = node["__children"]
        node["name"] = node["ImageFileName"]
        del node["__children"]
        del node["ImageFileName"]
        for children in node["children"]:
            rename_pstree(children)


def rename_devicetree(node):
    if len(node["__children"]) == 0:
        node["children"] = node["__children"]

        node["name"] = ""

        if node["DeviceName"]:
            node["name"] += node["DeviceName"]
        if node["DeviceType"]:
            node["name"] += "/" + node["DeviceType"]
        if node["DriverName"]:
            node["name"] += "/" + node["DriverName"]
        del node["__children"]
    else:
        node["children"] = node["__children"]

        node["name"] = ""

        if node["DeviceName"]:
            node["name"] += node["DeviceName"]
        if node["DeviceType"]:
            node["name"] += "/" + node["DeviceType"]
        if node["DriverName"]:
            node["name"] += "/" + node["DriverName"]

        del node["__children"]
        for children in node["children"]:
            rename_devicetree(children)


def run_volweb_routine_windows(instance):
    logger.info("Starting VolWeb Engine")
    volatility3.framework.require_interface_version(2, 0, 0)
    # TODO : DON'T FORGET ME
    # if case.linked_isf:
    #     path = os.sep.join(case.linked_isf.symbols_file.name.split(os.sep)[:-2])
    #     volatility3.symbols.__path__.append(os.path.abspath(path))
    """Import available plugings from the native framework"""
    failures = volatility3.framework.import_files(plugins, True)
    if failures:
        logger.info(f"Some volatility3 plugin couldn't be loaded : {failures}")
    else:
        logger.info(f"Plugins are loaded without failure")
    plugin_list = volatility3.framework.list_plugins()
    base_config_path = "plugins"

    """Full list of plugins supported by VolWeb"""
    volweb_knowledge_base = {
        # Process
        "PsScan": {"plugin": plugin_list["windows.psscan.PsScan"]},
        "PsTree": {"plugin": plugin_list["windows.pstree.PsTree"]},
        "DeviceTree": {"plugin": plugin_list["windows.devicetree.DeviceTree"]},
        "CmdLine": {"plugin": plugin_list["windows.cmdline.CmdLine"]},
        "GetSIDs": {"plugin": plugin_list["windows.getsids.GetSIDs"]},
        "Sessions": {"plugin": plugin_list["windows.sessions.Sessions"]},
        "Privs": {"plugin": plugin_list["windows.privileges.Privs"]},
        "Envars": {"plugin": plugin_list["windows.envars.Envars"]},
        "DllList": {"plugin": plugin_list["windows.dlllist.DllList"]},
        "LdrModules": {"plugin": plugin_list["windows.ldrmodules.LdrModules"]},
        "Modules": {"plugin": plugin_list["windows.modules.Modules"]},
        "VadWalk": {"plugin": plugin_list["windows.vadwalk.VadWalk"]},
        "SvcScan": {"plugin": plugin_list["windows.svcscan.SvcScan"]},
        # Network
        "NetScan": {"plugin": plugin_list["windows.netstat.NetStat"]},
        "NetStat": {"plugin": plugin_list["windows.netscan.NetScan"]},
        # Others
        "DriverModule": {"plugin": plugin_list["windows.drivermodule.DriverModule"]},
        # Cryptography
        "Hashdump": {"plugin": plugin_list["windows.hashdump.Hashdump"]},
        "Lsadump": {"plugin": plugin_list["windows.lsadump.Lsadump"]},
        "Cachedump": {"plugin": plugin_list["windows.cachedump.Cachedump"]},
        # Registry
        "HiveList": {"plugin": plugin_list["windows.registry.hivelist.HiveList"]},
        "UserAssist": {"plugin": plugin_list["windows.registry.userassist.UserAssist"]},
        # # Malware analysis
        "Timeliner": {"plugin": plugin_list["timeliner.Timeliner"]},
        "Malfind": {"plugin": plugin_list["windows.malfind.Malfind"]},
        "SSDT": {"plugin": plugin_list["windows.ssdt.SSDT"]},
        "SkeletonKeyCheck": {
            "plugin": plugin_list["windows.skeleton_key_check.Skeleton_Key_Check"]
        },
        "FileScan": {"plugin": plugin_list["windows.filescan.FileScan"]},
    }

    def update_progress(instance):
        """Progress Function"""
        MODULES_TO_RUN = len(volweb_knowledge_base)
        percentage = str(int(instance.dump_status) + 100 // MODULES_TO_RUN)
        instance.dump_status = percentage
        instance.save()

    json_pstree_artefact = []
    json_devicetree_artefact = []
    json_netgraph_artefact = []
    json_timeline_graph_artefact = []
    json_netgraph_artefact = []
    network_artefact = []
    for runable in volweb_knowledge_base:
        context = contexts.Context()
        apps.get_model("windows_engine", runable).objects.filter(
            evidence_id=instance.dump_id
        ).delete()
        logger.info(f"Constructing context for {runable} ")
        """Add pluging argument for hivelist"""
        if runable == "HiveList":
            context.config["plugins.HiveList.dump"] = True
        try:
            # TODO NEED TO SAVE THE KEY WITH THE EVIDENCE IN CASE OF NAME DUPLICATION
            constructed = build_context(
                instance,
                context,
                base_config_path,
                volweb_knowledge_base[runable]["plugin"],
                "Loot/" + str(instance.dump_id) + "/files/",
            )
        except Exception as e:
            logger.warning(f"Could not build context for {runable} : {e}")
            constructed = []

        if constructed:
            try:
                result = DictRenderer().render(constructed.run())
                if runable == "PsTree":
                    for tree in result:
                        rename_pstree(tree)
                    json_pstree_artefact = json.dumps(result)
                    PsTree(evidence=instance, graph=json_pstree_artefact).save()

                elif runable == "UserAssist":
                    fill_userassist(result, instance)

                elif runable == "DeviceTree":
                    for tree in result:
                        rename_devicetree(tree)
                    json_devicetree_artefact = json.dumps(result)
                    DeviceTree(evidence=instance, graph=json_devicetree_artefact).save()

                else:
                    for artefact in result:
                        artefact = {
                            x.translate({32: None}): y for x, y in artefact.items()
                        }
                        if "__children" in artefact:
                            del artefact["__children"]
                        if "Offset(V)" in artefact:
                            artefact["Offset"] = artefact["Offset(V)"]
                            del artefact["Offset(V)"]
                        if "Tag" in artefact:
                            artefact["VTag"] = artefact["Tag"]
                            del artefact["Tag"]

                        apps.get_model("windows_engine", runable)(
                            evidence_id=instance.dump_id, **artefact
                        ).save()

                if runable == "NetScan":
                    network_artefact = network_artefact + result
                if runable == "NetStat":
                    network_artefact = network_artefact + result
                if runable == "Timeliner":
                    TimeLineChart.objects.filter(evidence_id=instance.dump_id).delete()
                    json_timeline_graph_artefact = json.dumps(build_timeline(result))
                    TimeLineChart(
                        evidence=instance, graph=json_timeline_graph_artefact
                    ).save()

            except:
                logger.error(f"Could not run {runable}")
            update_progress(instance)

    json_netgraph_artefact = json.dumps(generate_network_graph(network_artefact))
    NetGraph(evidence=instance, graph=json_netgraph_artefact).save()
    instance.dump_status = 100
    instance.save()

