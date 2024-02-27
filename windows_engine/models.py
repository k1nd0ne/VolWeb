from django.db import models
from django.db import models
from evidences.models import Evidence
import base64
from VolWeb.voltools import build_context
from celery import shared_task
import logging, json
import volatility3
from volatility3.framework import contexts
from evidences.models import Evidence
from windows_engine.models import *
from volatility3 import plugins
from django.apps import apps
from VolWeb.voltools import *
from volatility3.framework.exceptions import *

volatility3.framework.require_interface_version(2, 0, 0)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

base_config_path = "plugins"
failures = volatility3.framework.import_files(plugins, True)
if failures:
    logger.error(f"Some volatility3 plugin couldn't be loaded : {failures}")
else:
    logger.info(f"Volatility3 Plugins are loaded without failure")

PLUGIN_LIST = volatility3.framework.list_plugins()

TAGS = (
    ("Evidence", "Evidence"),
    ("Suspicious", "Suspicious"),
    ("Clear", "Clear"),
)


class PsTree(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_pstree_evidence"
    )
    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="PsTree.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["windows.pstree.PsTree"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None

    def pslist_dump(self, pid):
        """Dump the process requested by the user using the pslist plugin"""
        evidence_data = {
            "bucket": f"s3://{str(self.evidence.dump_linked_case.case_bucket_id)}/{self.evidence.dump_name}",
            "output_path": f"media/{self.evidence.dump_id}/",
        }
        context = contexts.Context()
        context.config["plugins.PsList.pid"] = [
            pid,
        ]
        context.config["plugins.PsList.dump"] = True
        constructed = build_context(
            evidence_data,
            context,
            base_config_path,
            PLUGIN_LIST["windows.pslist.PsList"],
        )
        result = DictRenderer().render(constructed.run())
        artefact = {x.translate({32: None}): y for x, y in result[0].items()}
        return artefact["Fileoutput"]

    def memmap_dump(self, pid):
        """Dump the process requested by the user using the memmap plugin"""
        evidence_data = {
            "bucket": f"s3://{str(self.evidence.dump_linked_case.case_bucket_id)}/{self.evidence.dump_name}",
            "output_path": f"media/{self.evidence.dump_id}/",
        }
        context = contexts.Context()
        context.config["plugins.Memmap.pid"] = int(pid)
        context.config["plugins.Memmap.dump"] = True
        constructed = build_context(
            evidence_data,
            context,
            base_config_path,
            PLUGIN_LIST["windows.memmap.Memmap"],
        )
        result = DictRenderer().render(constructed.run())
        artefact = {x.translate({32: None}): y for x, y in result[0].items()}
        return artefact["Fileoutput"]


class DeviceTree(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_devicetree_evidence"
    )
    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="DeviceTree.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["windows.devicetree.DeviceTree"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None


class NetGraph(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_netgraph_evidence"
    )
    artefacts = models.JSONField(null=True)


class TimeLineChart(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_timeline_evidence"
    )
    artefacts = models.JSONField(null=True)


class PsScan(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_psscan_evidence"
    )
    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="PsScan.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["windows.psscan.PsScan"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None


class CmdLine(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_cmdline_evidence"
    )
    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="CmdLine.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["windows.cmdline.CmdLine"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None


class Privs(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_privs_evidence"
    )
    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="Privs.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["windows.privileges.Privs"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None


class Sessions(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_sessions_evidence"
    )
    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="Sessions.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["windows.sessions.Sessions"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None


class GetSIDs(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_getsids_evidence"
    )
    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="GetSIDs.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["windows.getsids.GetSIDs"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None


class LdrModules(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_ldrmodules_evidence"
    )
    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="LdrModules.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["windows.ldrmodules.LdrModules"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None


class Modules(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_modules_evidence"
    )
    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="Modules.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["windows.modules.Modules"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None


class SvcScan(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_svcscan_evidence"
    )
    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="SvcScan.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["windows.svcscan.SvcScan"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None


class Envars(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_envars_evidence"
    )
    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="Envars.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["windows.envars.Envars"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None


class NetScan(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_netscan_evidence"
    )
    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="NetScan.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["windows.netscan.NetScan"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None


class NetStat(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_netstat_evidence"
    )
    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="NetStat.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["windows.netstat.NetStat"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None


class Hashdump(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_hashdump_evidence"
    )
    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="Hashdump.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["windows.hashdump.Hashdump"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None


class Lsadump(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_lsadump_evidence"
    )
    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="Lsadump.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["windows.lsadump.Lsadump"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                for artefact in result:
                    encode = base64.b64encode(artefact["Secret"], "utf-8")
                    artefact["Secret"] = encode
                return result
        except:
            return None


class Cachedump(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_cachedump_evidence"
    )

    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="Cachedump.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["windows.cachedump.Cachedump"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None


class HiveList(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_hivelist_evidence"
    )
    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="HiveList.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            context.config["plugins.HiveList.dump"] = True
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["windows.registry.hivelist.HiveList"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None


class Timeliner(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_timeliner_evidence"
    )

    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="Timeliner.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["timeliner.Timeliner"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None


class SkeletonKeyCheck(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_skc_evidence"
    )

    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="SkeletonKeyCheck.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["windows.skeleton_key_check.Skeleton_Key_Check"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None


class Malfind(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_malfind_evidence"
    )

    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="Malfind.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["windows.malfind.Malfind"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None


class UserAssist(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_userassist_evidence"
    )

    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="UserAssist.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["windows.registry.userassist.UserAssist"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None


class MFTScan(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_mftscan_evidence"
    )

    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="MFTScan.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["windows.mftscan.MFTScan"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None

class ADS(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_ads_evidence"
    )

    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="ADS.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["windows.mftscan.ADS"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None

class MBRScan(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_mbrscan_evidence"
    )

    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="MBRScan.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["windows.mbrscan.MBRScan"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None


class FileScan(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_filescan_evidence"
    )

    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="FileScan.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["windows.filescan.FileScan"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None

    def file_dump(self, offset):
        evidence_data = {
            "bucket": f"s3://{str(self.evidence.dump_linked_case.case_bucket_id)}/{self.evidence.dump_name}",
            "output_path": f"media/{self.evidence.dump_id}/",
        }
        """Dump the file requested by the user"""
        context = contexts.Context()
        context.config["plugins.DumpFiles.virtaddr"] = int(offset)
        try:
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["windows.dumpfiles.DumpFiles"],
            )
            result = DictRenderer().render(constructed.run())
            if len(result) == 0:
                del context.config["plugins.DumpFiles.virtaddr"]
                context.config["plugins.DumpFiles.physaddr"] = int(offset)
                constructed = build_context(
                    evidence_data,
                    context,
                    base_config_path,
                    PLUGIN_LIST["windows.dumpfiles.DumpFiles"],
                )
            result = DictRenderer().render(constructed.run())
            for artefact in result:
                artefact = {x.translate({32: None}): y for x, y in artefact.items()}
            return result
        except:
            return None


class DllList(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_dllist_evidence"
    )

    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="DllList.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["windows.dlllist.DllList"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None


class Handles(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_handles_evidence"
    )
    PID = models.BigIntegerField()
    artefacts = models.JSONField(null=True)

    def run(self, pid):
        """Compute Handles for a specific PID"""
        evidence_data = {
            "bucket": f"s3://{str(self.evidence.dump_linked_case.case_bucket_id)}/{self.evidence.dump_name}",
            "output_path": None,
        }
        context = contexts.Context()
        context.config["plugins.Handles.pid"] = [int(pid)]
        try:
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["windows.handles.Handles"],
            )
            result = DictRenderer().render(constructed.run())
            self.artefacts = result
            self.PID = pid
            self.save()
            return self
        except:
            return None


class DriverModule(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_drivermodule_evidence"
    )

    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="DriverModule.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["windows.drivermodule.DriverModule"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None


class VadWalk(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_vadwalk_evidence"
    )

    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="VadWalk.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["windows.vadwalk.VadWalk"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None


class SSDT(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_ssdt_evidence"
    )

    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="SSDT.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["windows.ssdt.SSDT"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None


class Loot(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_loot"
    )
    FileName = models.TextField(null=True)
    Name = models.TextField()
    Status = models.BooleanField()
