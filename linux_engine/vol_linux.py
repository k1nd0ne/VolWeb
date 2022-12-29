import logging, jsonschema
from investigations.models import *
from .models import *
from django.apps import apps
from VolWeb.voltools import *
from volatility3.cli import MuteProgress
from volatility3.framework.exceptions import *

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def build_context(dump_path, context, base_config_path, plugin, output_path):
    """This function is used to buid the context and construct each plugin
       Return : The contructed plugin.
    """
    available_automagics = automagic.available(context)
    plugin_config_path = interfaces.configuration.path_join(base_config_path, plugin.__name__)
    automagics = automagic.choose_automagic(available_automagics, plugin)
    context.config['automagic.LayerStacker.stackers'] = automagic.stacker.choose_os_stackers(plugin)
    context.config['automagic.LayerStacker.single_location'] = "file://" + os.getcwd() + "/" + dump_path
    constructed = construct_plugin(context, automagics, plugin, base_config_path, MuteProgress(), file_handler(output_path))
    return constructed


def get_procmaps(dump_path, pid, case):
    """Compute ProcMaps for a specific PID"""
    volatility3.framework.require_interface_version(2, 0, 0)
    """ISF Binding"""
    if case.linked_isf:
        path = os.sep.join(case.linked_isf.symbols_file.name.split(os.sep)[:-2])
        volatility3.symbols.__path__.append(os.path.abspath(path))
    failures = volatility3.framework.import_files(plugins, True)
    if failures:
        logger.info(f"Some volatility3 plugin couldn't be loaded : {failures}")
    else:
        logger.info(f"Plugins are loaded without failure")
    plugin_list = volatility3.framework.list_plugins()
    base_config_path = "plugins"
    context = contexts.Context()
    context.config['plugins.Maps.pid'] = [int(pid)]
    constructed = build_context(dump_path, context, base_config_path, plugin_list['linux.proc.Maps'], output_path=None)
    if constructed:
        result = DictRenderer().render(constructed.run())
    else:
        logger.info("Error the procMaps could not be computed")
        return "KO"
    for artifact in result:
        artifact = {x.translate({32: None}): y
                    for x, y in artifact.items()}
        del (artifact['__children'])
        ProcMaps(investigation_id=case.id, **artifact).save()
    return "OK"




def run_volweb_routine_linux(dump_path, case_id, case):
    partial_results = False
    logger.info('Starting VolWeb Engine')
    volatility3.framework.require_interface_version(2, 0, 0)
    """ISF Binding"""
    if case.linked_isf:
        path = os.sep.join(case.linked_isf.symbols_file.name.split(os.sep)[:-2])
        volatility3.symbols.__path__.append(os.path.abspath(path))

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
        'PsList': {'plugin': plugin_list['linux.pslist.PsList']},
        'PsAux': {'plugin': plugin_list['linux.psaux.PsAux']},
        'PsTree': {'plugin': plugin_list['linux.pstree.PsTree']},
        'Bash': {'plugin': plugin_list['linux.bash.Bash']},
        'Lsof': {'plugin': plugin_list['linux.lsof.Lsof']},
        'Elfs': {'plugin': plugin_list['linux.elfs.Elfs']},

        # Malware analysis
        'TtyCheck': {'plugin': plugin_list['linux.tty_check.tty_check']},
        'MountInfo': {'plugin': plugin_list['linux.mountinfo.MountInfo']},
    }

    """Progress Function"""

    def update_progress(case):
        MODULES_TO_RUN = len(volweb_knowledge_base) * 2
        percentage = str(format(float(case.percentage) + float(100 / MODULES_TO_RUN), '.0f'))
        logger.info(f"Status : {percentage} %")
        case.percentage = percentage
        case.save()

    """STEP 0 : Clear the current signatures and compute the memory image signatures"""
    logger.info("Constructing memory image signatures...")
    ImageSignature.objects.filter(investigation_id=case_id).delete()
    signatures = memory_image_hash(dump_path)
    ImageSignature(investigation_id=case_id, **signatures).save()

    """STEP 1 : Clean database and build the basic context for each plugin"""
    for runable in volweb_knowledge_base:
        apps.get_model("linux_engine", runable).objects.filter(investigation_id=case_id).delete()
        context = contexts.Context()
        logger.info(f"Constructing context for {runable} ")
        try:
            volweb_knowledge_base[runable]['constructed'] = build_context(dump_path, context, base_config_path,
                                                                          volweb_knowledge_base[runable]['plugin'],output_path=None)
        except VolatilityException:
            partial_results = True
            volweb_knowledge_base[runable]['constructed'] = []
        except:
            logger.info(f"Could not build context for {runable}" )
            partial_results = True
            volweb_knowledge_base[runable]['constructed'] = []
        update_progress(case)


    """STEP 2.1 : For each constructed plugin's context, we render the result and save it."""
    for runable in volweb_knowledge_base:
        if volweb_knowledge_base[runable]['constructed']:
            logger.info(f"Running plugin : {runable}")
            try:
                volweb_knowledge_base[runable]['result'] = DictRenderer().render(volweb_knowledge_base[runable]['constructed'].run())
            except VolatilityException:
                partial_results = True
                volweb_knowledge_base[runable]['result'] = []
            except:
                logger.info(f"Could not run {runable}" )
                partial_results = True
                volweb_knowledge_base[runable]['result'] = []
        else:
            volweb_knowledge_base[runable]['result'] = []
        update_progress(case)


    """STEP 3.1 : We can now inject the results inside the database"""
    for runable in volweb_knowledge_base:
        if runable != 'PsTree':
            for artifact in volweb_knowledge_base[runable]['result']:
                artifact = {x.translate({32: None}): y
                            for x, y in artifact.items()}
                if '__children' in artifact:
                    del (artifact['__children'])
                if 'OFFSET(V)' in artifact:
                    artifact['Offset'] = artifact['OFFSET(V)']
                    del (artifact['OFFSET(V)'])
                if "MAJOR:MINOR" in artifact:
                    artifact['MAJOR_MINOR'] = artifact['MAJOR:MINOR']
                    del (artifact['MAJOR:MINOR'])

                apps.get_model("linux_engine", runable)(investigation_id=case_id, **artifact).save()

    """STEP 3.2 : Contruct and inject the graphs"""

    def rename(node):
        if len(node['__children']) == 0:
            node['children'] = node['__children']
            node['name'] = node['COMM']
            del (node['__children'])
            del (node['COMM'])
        else:
            node['children'] = node['__children']
            node['name'] = node['COMM']
            del (node['__children'])
            del (node['COMM'])
            for children in node['children']:
                rename(children)

    json_pstree_artifact = []
    if volweb_knowledge_base['PsTree']['result']:
        pstree_artifact = volweb_knowledge_base['PsTree']['result']
        for tree in pstree_artifact:
            rename(tree)
        json_pstree_artifact = json.dumps(pstree_artifact)

    apps.get_model("linux_engine", "PsTree")(investigation_id=case_id, graph=json_pstree_artifact).save()
    return partial_results
