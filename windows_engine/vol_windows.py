import logging
from investigations.models import *
from windows_engine.models import *
from iocs.models import *
from django.apps import apps
from VolWeb.voltools import *
from volatility3.framework.exceptions import *
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def build_context(dump_path ,context, base_config_path, plugin, output_path):
    """This function is used to buid the context and construct each plugin
       Return : The contructed plugin.
    """
    available_automagics = automagic.available(context)
    plugin_config_path = interfaces.configuration.path_join(base_config_path, plugin.__name__)
    automagics = automagic.choose_automagic(available_automagics, plugin)
    context.config['automagic.LayerStacker.stackers'] = automagic.stacker.choose_os_stackers(plugin)
    context.config['automagic.LayerStacker.single_location'] = "file://" + os.getcwd() + "/" + dump_path
    constructed = construct_plugin(context, automagics, plugin, base_config_path, None, file_handler(output_path))
    return constructed


def collect_user_iocs(case,dump_path):
    """This function is used to look for string based iocs using the volatility3 strings module.
    """
    logger.info("Collecting IOCs from user's string based IOCs")
    iocs = IOC.objects.all()

    terms = ""
    ioc_result_name = "Cases/IOCs/iocs_invest_" + str(case.id)
    strings_output_file = "Cases/IOCs/output_"+ str(case.id)
    with open(ioc_result_name, 'w') as fout:
        fout.write('')
        fout.close()

    for ioc in iocs:
        if (case.id == ioc.linkedInvestigation.id):
            terms = terms + ioc.value + "|"
    if terms != "":
        with open(strings_output_file, 'w') as fout:
            try:
                fout.write(subprocess.check_output(['strings', '-t', 'd', dump_path]).decode())
            except subprocess.CalledProcessError as e:
                logger.info("Could not execute the strings command : ", e.output)
            fout.close()
        with open(ioc_result_name, 'w') as fout:
            try:
                fout.write(subprocess.check_output(['grep', '-E', terms[:len(terms)-1] ,  strings_output_file]).decode())
            except subprocess.CalledProcessError as e:
                logger.info("No IOCs found : ",e.output)
            fout.close()
    f_len = os.path.getsize(ioc_result_name)
    if f_len <= 1:
        result = {}
        Strings(investigation_id = case.id, **result).save()
        return
    volatility3.framework.require_interface_version(2, 0, 0)
    failures = volatility3.framework.import_files(plugins, True)
    if failures:
        logger.info(f"Some volatility3 plugin couldn't be loaded : {failures}")
    else:
        logger.info(f"Plugins are loaded without failure")
    plugin_list = volatility3.framework.list_plugins()
    base_config_path = "plugins"
    context = contexts.Context()
    context.config['plugins.Strings.strings_file'] = "file://" + os.getcwd() + "/" + ioc_result_name
    constructed = build_context(dump_path, context, base_config_path, plugin_list['windows.strings.Strings'], output_path = None)
    if constructed:
        result = DictRenderer().render(constructed.run())
        for artifact in result:
            artifact = { x.translate({32:None}) : y
                for x, y in artifact.items()}
            del(artifact['__children'])
            Strings(investigation_id = case.id, **artifact).save()

def dump_process(dump_path, pid, output_path):
    """Dump the process requested by the user"""
    volatility3.framework.require_interface_version(2, 0, 0)
    failures = volatility3.framework.import_files(plugins, True)
    if failures:
        logger.info(f"Some volatility3 plugin couldn't be loaded : {failures}")
    else:
        logger.info(f"Plugins are loaded without failure")
    plugin_list = volatility3.framework.list_plugins()
    base_config_path = "plugins"
    context = contexts.Context()
    context.config['plugins.PsList.pid'] = [int(pid)]
    context.config['plugins.PsList.dump'] = True
    constructed = build_context(dump_path, context, base_config_path, plugin_list['windows.pslist.PsList'], output_path)
    if constructed:
        result = DictRenderer().render(constructed.run())
    else:
        logger.info("Error")
    for artifact in result:
        artifact = { x.translate({32:None}) : y
            for x, y in artifact.items()}
    return artifact['Fileoutput']

def dump_file(dump_path, offset, output_path):
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
    context.config['plugins.DumpFiles.virtaddr'] = int(offset)
    try:
        constructed = build_context(dump_path, context, base_config_path, plugin_list['windows.dumpfiles.DumpFiles'], output_path)
    except:
        logger.info("Cannot build")
    if constructed:
        result = DictRenderer().render(constructed.run())
        if not result:
            del(context.config['plugins.DumpFiles.virtaddr'])
            context.config['plugins.DumpFiles.physaddr'] = int(offset)
            constructed = build_context(dump_path, context, base_config_path, plugin_list['windows.dumpfiles.DumpFiles'], output_path)
            result = DictRenderer().render(constructed.run())
    for artifact in result:
        artifact = { x.translate({32:None}) : y
            for x, y in artifact.items()}
    return result[0]['Result']

def run_volweb_routine_windows(dump_path, case_id, case):
    PARTIAL_RESULTS = False
    logger.info('Starting VolWeb Engine')
    volatility3.framework.require_interface_version(2, 0, 0)
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
    #Process
        'PsScan' : {'plugin' : plugin_list['windows.psscan.PsScan']},
        'PsTree' : {'plugin' : plugin_list['windows.pstree.PsTree']},
        'CmdLine' : {'plugin' : plugin_list['windows.cmdline.CmdLine']},
        'Privs' : {'plugin': plugin_list['windows.privileges.Privs']},
        'Envars' : {'plugin': plugin_list['windows.envars.Envars']},
        'DllList' : {'plugin': plugin_list['windows.dlllist.DllList']},
        'Handles' : {'plugin': plugin_list['windows.handles.Handles']},
    #Network
        'NetScan' : {'plugin': plugin_list['windows.netstat.NetStat']},
        'NetStat' : {'plugin': plugin_list['windows.netscan.NetScan']},

    #Cryptography
        'Hashdump' : {'plugin': plugin_list['windows.hashdump.Hashdump']},
        'Lsadump' : {'plugin': plugin_list['windows.lsadump.Lsadump']},
        'Cachedump' : {'plugin' : plugin_list['windows.cachedump.Cachedump']},

    #Registry
        'HiveList' : {'plugin' : plugin_list['windows.registry.hivelist.HiveList']},
        'UserAssist' : {'plugin': plugin_list['windows.registry.userassist.UserAssist']},

    #Malware analysis
        'Timeliner': {'plugin' : plugin_list['timeliner.Timeliner']},
        'Malfind' : {'plugin' : plugin_list['windows.malfind.Malfind']},
        'SkeletonKeyCheck': {'plugin' : plugin_list['windows.skeleton_key_check.Skeleton_Key_Check']},
        'FileScan' : {'plugin' : plugin_list['windows.filescan.FileScan']},
    }
    """Progress Function"""
    def update_progress(case):
        MODULES_TO_RUN = len(volweb_knowledge_base) + 2
        percentage = str(format(float(case.percentage) + float(100/MODULES_TO_RUN), '.0f'))
        logger.info(f"Status : {percentage} %")
        case.percentage = percentage
        case.save()

    """STEP 0 : Clear the current signatures and compute the memory image signatures"""
    logger.info("Constructing memory image signatures...")
    ImageSignature.objects.filter(investigation_id = case_id).delete()
    signatures = memory_image_hash(dump_path)
    ImageSignature(investigation_id = case_id, **signatures).save()
    update_progress(case)

    """STEP 1 : Clean database and build the basic context for each plugin"""
    NetGraph.objects.filter(investigation_id = case_id).delete()
    TimeLineChart.objects.filter(investigation_id = case_id).delete()
    Strings.objects.filter(investigation_id = case_id).delete()
    for runable in volweb_knowledge_base:
        apps.get_model("windows_engine", runable).objects.filter(investigation_id = case_id).delete()
        context = contexts.Context()
        logger.info(f"Constructing context for {runable} ")
        """Add pluging argument for hivelist"""
        if runable == 'HiveList':
            context.config['plugins.HiveList.dump'] = True
        try:
            volweb_knowledge_base[runable]['constructed'] = build_context(dump_path, context, base_config_path, volweb_knowledge_base[runable]['plugin'],"Cases/files")
        except VolatilityException:
            PARTIAL_RESULTS = True
            volweb_knowledge_base[runable]['constructed'] = []

    """STEP 2.1 : For each constructed plugin's context, we render the result and save it."""
    for runable in volweb_knowledge_base:
        if volweb_knowledge_base[runable]['constructed']:
            logger.info(f"Running plugin : {runable}")
            try:
                volweb_knowledge_base[runable]['result'] = DictRenderer().render(volweb_knowledge_base[runable]['constructed'].run())
            except VolatilityException:
                PARTIAL_RESULTS = True
                volweb_knowledge_base[runable]['result'] = []
            update_progress(case)
        else:
            volweb_knowledge_base[runable]['result'] = []
            update_progress(case)

    """STEP 2.2 : Look for string based iocs"""
    collect_user_iocs(case,dump_path)
    update_progress(case)

    """STEP 3.1 : We can now inject the results inside the django database"""
    for runable in volweb_knowledge_base:
        if runable != 'PsTree' and runable != 'UserAssist':
            for artifact in volweb_knowledge_base[runable]['result']:
                artifact = { x.translate({32:None}) : y
                    for x, y in artifact.items()}
                if '__children' in artifact:
                    del(artifact['__children'])
                if 'Offset(V)' in artifact:
                    artifact['Offset'] = artifact['Offset(V)']
                    del(artifact['Offset(V)'])

                apps.get_model("windows_engine", runable)(investigation_id = case_id, **artifact).save()

    """STEP 3.2 : Contruct and inject the graphs"""
    def rename(node):
        if len(node['__children']) == 0:
            node['children'] = node['__children']
            node['name'] = node['ImageFileName']
            del(node['__children'])
            del(node['ImageFileName'])
        else:
            node['children'] = node['__children']
            node['name'] = node['ImageFileName']
            del(node['__children'])
            del(node['ImageFileName'])
            for children in node['children']:
                rename(children)
    json_pstree_artifact = []
    json_netgraph_artifact = []
    json_timelinegraph_artifact = []
    if volweb_knowledge_base['PsTree']['result']:
        pstree_artifact = volweb_knowledge_base['PsTree']['result']
        for tree in pstree_artifact:
            rename(tree)
        json_pstree_artifact = json.dumps(pstree_artifact)


    if volweb_knowledge_base['NetScan']['result'] or volweb_knowledge_base['NetStat']['result']:
        json_netgraph_artifact = json.dumps(generate_network_graph(volweb_knowledge_base['NetScan']['result'] + volweb_knowledge_base['NetStat']['result']))

    if volweb_knowledge_base['Timeliner']['result']:
        json_timelinegraph_artifact = json.dumps(build_timeline(volweb_knowledge_base['Timeliner']['result']))

    PsTree(investigation_id = case_id, graph = json_pstree_artifact).save()
    NetGraph(investigation_id = case_id, graph = json_netgraph_artifact).save()
    TimeLineChart(investigation_id = case_id, graph = json_timelinegraph_artifact).save()

    def UserAssistFill(list,case_id):
        for artifact in list:
            artifact = { x.translate({32:None}) : y
                for x, y in artifact.items()}
            apps.get_model("windows_engine", 'UserAssist')(investigation_id = case_id,
                HiveOffset = artifact['HiveOffset'],
                HiveName =  artifact['HiveName'],
                Path = artifact['Path'],
                LastWriteTime = artifact['LastWriteTime'],
                Type = artifact['Type'],
                Name =artifact['Name'],
                ID = artifact['ID'],
                Count = artifact['Count'],
                FocusCount = artifact['FocusCount'],
                TimeFocused = artifact['TimeFocused'],
                LastUpdated = artifact['LastUpdated'],
                RawData  = artifact['RawData']).save()
            if artifact['__children']:
                UserAssistFill(artifact['__children'],case_id)

    if volweb_knowledge_base['UserAssist']['result']:
        UserAssistFill(volweb_knowledge_base['UserAssist']['result'],case_id)

    return PARTIAL_RESULTS
