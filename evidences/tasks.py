from celery import shared_task
import evidences
from evidences.models import Evidence
import windows_engine.models as windows
import linux_engine.models as linux
from VolWeb.voltools import (
    build_timeline,
    generate_windows_network_graph,
    generate_linux_network_graph,
)
from VolWeb.voltools import fix_permissions
from celery.result import allow_join_result
from celery import group
import os, time


@shared_task
def start_analysis(dump_id):
    """
    The main analysis routine for both Windows and Linux.
    """
    instance = Evidence.objects.get(dump_id=dump_id)
    output_path = f"media/{instance.dump_id}/"
    if not os.path.exists(os.path.dirname(output_path)):
        os.makedirs(os.path.dirname(output_path))
    evidence_data = {
        "bucket": f"s3://{str(instance.dump_linked_case.case_bucket_id)}/{instance.dump_name}",
        "output_path": output_path,
    }
    if instance.dump_os == "Windows":
        # We need to download the pdb in a single thread because volatility3 doesn't like multithreading when fetching ISF.
        # I'll try to propose a fix to the volatility3 team so this bug is fixed in future releases.
        # For this I am running the Windows.Info pluging first just so that the pdbfile is downloaded and cached in a single thread.
        # This method only works with a single celery worker. No problem if the ISF are imported offline.
        windows.Info(evidence=instance).run(evidence_data)
        volweb_plugins = [
            windows.PsScan(evidence=instance),
            windows.PsTree(evidence=instance),
            windows.DeviceTree(evidence=instance),
            windows.CmdLine(evidence=instance),
            windows.Privs(evidence=instance),
            windows.Sessions(evidence=instance),
            windows.GetSIDs(evidence=instance),
            windows.LdrModules(evidence=instance),
            windows.Modules(evidence=instance),
            windows.SvcScan(evidence=instance),
            windows.Envars(evidence=instance),
            windows.NetScan(evidence=instance),
            windows.NetStat(evidence=instance),
            windows.Hashdump(evidence=instance),
            windows.Lsadump(evidence=instance),
            windows.Cachedump(evidence=instance),
            windows.HiveList(evidence=instance),
            windows.Timeliner(evidence=instance),
            windows.SkeletonKeyCheck(evidence=instance),
            windows.Malfind(evidence=instance),
            windows.UserAssist(evidence=instance),
            windows.FileScan(evidence=instance),
            windows.DllList(evidence=instance),
            windows.DriverModule(evidence=instance),
            windows.VadWalk(evidence=instance),
            windows.SSDT(evidence=instance),
            windows.MFTScan(evidence=instance),
            windows.ADS(evidence=instance),
            windows.MBRScan(evidence=instance),
        ]

        task_group = group(plugin.run.s(evidence_data) for plugin in volweb_plugins)
        group_result = task_group.apply_async()

        while not group_result.ready():
            completed_tasks = len([r for r in group_result.results if r.ready()])
            total_tasks = len(group_result.results)
            status = (completed_tasks * 100) / total_tasks
            if instance.dump_status != status:
                instance.dump_status = (completed_tasks * 100) / total_tasks
                instance.save()
            time.sleep(1)

        with allow_join_result():
            logs = {}
            result = group_result.get()
            for i in range(0, len(result)):
                plugin_name = volweb_plugins[i].__class__.__name__
                if result[i] == "Unsatisfied":
                    logs[plugin_name] = "Unsatisfied"
                    result[i] = None
                elif result[i]:
                    logs[plugin_name] = "Success"
                else:
                    logs[plugin_name] = "Failed"

                volweb_plugins[i].__class__.objects.filter(evidence=instance).delete()
                volweb_plugins[i].artefacts = result[i]
                volweb_plugins[i].save()

            windows.TimeLineChart.objects.filter(evidence=instance).delete()
            if result[17]:
                windows.TimeLineChart(
                    evidence=instance, artefacts=build_timeline(result[17])
                ).save()

            windows.NetGraph.objects.filter(evidence=instance).delete()
            if result[11] and result[12]:
                windows.NetGraph(
                    evidence=instance,
                    artefacts=generate_windows_network_graph(result[11] + result[12]),
                ).save()
            else:
                if result[11]:
                    windows.NetGraph(
                        evidence=instance,
                        artefacts=generate_windows_network_graph(result[11]),
                    ).save()
                if result[12]:
                    windows.NetGraph(
                        evidence=instance,
                        artefacts=generate_windows_network_graph(result[12]),
                    ).save()
            fix_permissions(output_path)
            instance.dump_logs = logs
            instance.dump_status = 100
            instance.save()
    if instance.dump_os == "Linux":
        volweb_plugins = [
            linux.PsTree(evidence=instance),
            linux.PsAux(evidence=instance),
            linux.PsScan(evidence=instance),
            linux.Lsof(evidence=instance),
            linux.Bash(evidence=instance),
            linux.Elfs(evidence=instance),
            linux.Sockstat(evidence=instance),
            linux.Timeliner(evidence=instance),
            linux.Capabilities(evidence=instance),
            linux.Kmsg(evidence=instance),
            linux.Malfind(evidence=instance),
            linux.Lsmod(evidence=instance),
            linux.Envars(evidence=instance),
            linux.MountInfo(evidence=instance),
            linux.tty_check(evidence=instance),
        ]

        task_group = group(plugin.run.s(evidence_data) for plugin in volweb_plugins)
        group_result = task_group.apply_async()

        while not group_result.ready():
            completed_tasks = len([r for r in group_result.results if r.ready()])
            total_tasks = len(group_result.results)
            status = (completed_tasks * 100) / total_tasks
            if instance.dump_status != status:
                instance.dump_status = (completed_tasks * 100) / total_tasks
                instance.save()
            time.sleep(1)

        with allow_join_result():
            logs = {}
            result = group_result.get()
            for i in range(0, len(result)):
                plugin_name = volweb_plugins[i].__class__.__name__
                if result[i] == "Unsatisfied":
                    logs[plugin_name] = "Unsatisfied"
                    result[i] = None
                elif result[i]:
                    logs[plugin_name] = "Success"
                else:
                    logs[plugin_name] = "Failed"

                volweb_plugins[i].__class__.objects.filter(evidence=instance).delete()
                volweb_plugins[i].artefacts = result[i]
                volweb_plugins[i].save()

            linux.NetGraph.objects.filter(evidence=instance).delete()
            if result[6]:
                linux.NetGraph(
                    evidence=instance, artefacts=generate_linux_network_graph(result[6])
                ).save()

            linux.TimeLineChart.objects.filter(evidence=instance).delete()
            if result[7]:
                linux.TimeLineChart(
                    evidence=instance, artefacts=build_timeline(result[7])
                ).save()
            fix_permissions(output_path)
            instance.dump_logs = logs
            instance.dump_status = 100
            instance.save()
