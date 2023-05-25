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


def run_volweb_routine_macos(dump_path, case_id, case):
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
        'Bash': {'plugin': plugin_list['mac.bash.Bash']},
        'PsList': {'plugin': plugin_list['mac.pslist.PsList']},
        'PsTree': {'plugin': plugin_list['mac.pstree.PsTree']},
        
        'Check_syscall': {'plugin': plugin_list['mac.check_syscall.Check_syscall']},
        'Check_sysctl': {'plugin': plugin_list['mac.check_sysctl.Check_sysctl']},
        'Check_trap_table': {'plugin': plugin_list['mac.check_trap_table.Check_trap_table']},
        'Ifconfig': {'plugin': plugin_list['mac.ifconfig.Ifconfig']},
        #'Kauth_listeners': {'plugin': plugin_list['mac.kauth_listeners.Kauth_listeners']},
        #'Kauth_scopes': {'plugin': plugin_list['mac.kauth_scopes.Kauth_scopes']},
        #'Kevents': {'plugin': plugin_list['mac.kevents.Kevents']},
        'List_Files': {'plugin': plugin_list['mac.list_files.List_Files']},
        'Lsmod': {'plugin': plugin_list['mac.lsmod.Lsmod']},
        'Lsof': {'plugin': plugin_list['mac.lsof.Lsof']},
        'Malfind': {'plugin': plugin_list['mac.malfind.Malfind']},
        'Mount': {'plugin': plugin_list['mac.mount.Mount']},
        'Netstat': {'plugin': plugin_list['mac.netstat.Netstat']},
        'Maps': {'plugin': plugin_list['mac.proc_maps.Maps']},
        'Psaux': {'plugin': plugin_list['mac.psaux.Psaux']},
        'Socket_filters': {'plugin': plugin_list['mac.socket_filters.Socket_filters']},
        #'Timers': {'plugin': plugin_list['mac.timers.Timers']},
        #'Trustedbsd': {'plugin': plugin_list['mac.trustedbsd.Trustedbsd']},
        'VFSevents': {'plugin': plugin_list['mac.vfsevents.VFSevents']},
    }

    """Progress Function"""

    def update_progress(case):
        MODULES_TO_RUN = len(volweb_knowledge_base) * 2
        percentage = str( int(case.percentage) + 100 // MODULES_TO_RUN)
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
        apps.get_model("macos_engine", runable).objects.filter(investigation_id=case_id).delete()
        context = contexts.Context()
        logger.info(f"Constructing context for {runable} ")
        try:
            volweb_knowledge_base[runable]['constructed'] = build_context(dump_path, context, base_config_path, volweb_knowledge_base[runable]['plugin'],output_path=None)
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

                apps.get_model("macos_engine", runable)(investigation_id=case_id, **artifact).save()

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

    apps.get_model("macos_engine", "PsTree")(investigation_id=case_id, graph=json_pstree_artifact).save()
    return partial_results
