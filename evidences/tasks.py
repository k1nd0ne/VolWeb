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
from celery.result import allow_join_result
from celery import group
import os, time


@shared_task
def start_analysis(dump_id):
    instance = Evidence.objects.get(dump_id=dump_id)
    output_path = f"media/{instance.dump_id}/"
    if not os.path.exists(os.path.dirname(output_path)):
        os.makedirs(os.path.dirname(output_path))
    evidence_data = {
        "bucket": f"s3://{str(instance.dump_linked_case.case_bucket_id)}/{instance.dump_name}",
        "output_path": output_path,
    }
    if instance.dump_os == "Windows":
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
            result = group_result.get()
            for i in range(0, len(result)):
                volweb_plugins[i].artefacts = result[i]
                volweb_plugins[i].save()

            # We need to take care of some specific models
            if result[17]:
                windows.TimeLineChart(
                    evidence=instance, artefacts=build_timeline(result[17])
                ).save()
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
            result = group_result.get()
            for i in range(0, len(result)):
                volweb_plugins[i].artefacts = result[i]
                volweb_plugins[i].save()

            if result[6]:
                linux.NetGraph(
                    evidence=instance, artefacts=generate_linux_network_graph(result[6])
                ).save()

            if result[7]:
                linux.TimeLineChart(
                    evidence=instance, artefacts=build_timeline(result[7])
                ).save()
            instance.dump_status = 100
            instance.save()
