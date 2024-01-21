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


def build_context(evidence_data, context, base_config_path, plugin):
    """This function is used to buid the context and construct each plugin
    Return : The contructed plugin.
    """
    available_automagics = automagic.available(context)
    automagics = automagic.choose_automagic(available_automagics, plugin)
    context.config[
        "automagic.LayerStacker.stackers"
    ] = automagic.stacker.choose_os_stackers(plugin)
    context.config["automagic.LayerStacker.single_location"] = (evidence_data["bucket"])
    constructed = construct_plugin(
        context,
        automagics,
        plugin,
        base_config_path,
        MuteProgress(),
        file_handler(evidence_data["output_path"]),
    )
    return constructed


def file_dump(instance, offset):
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
    output_path = f"media/{instance.dump_id}/"
    if not os.path.exists(os.path.dirname(output_path)):
        os.makedirs(os.path.dirname(output_path))
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
        output_path = f"media/{instance.dump_id}/"
        if not os.path.exists(os.path.dirname(output_path)):
            os.makedirs(os.path.dirname(output_path))
        try:
            constructed = build_context(
                instance,
                context,
                base_config_path,
                volweb_knowledge_base[runable]["plugin"],
                output_path,
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

