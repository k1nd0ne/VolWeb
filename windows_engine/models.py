from django.db import models
from django.db import models
from evidences.models import Evidence
import base64
from vol_windows import build_context, clean_result  # TODO: merge to voltools.py
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
    graph = models.JSONField(null=True)

    @staticmethod
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
                PsTree.rename_pstree(children)

    def run(self):
        context = contexts.Context()
        constructed = build_context(
            self.evidence,
            context,
            base_config_path,
            PLUGIN_LIST["windows.pstree.PsTree"],
        )
        if constructed:
            result = DictRenderer().render(constructed.run())
            for tree in result:
                self.rename_pstree(tree)
            self.graph = json.dumps(result)

    def pslist_dump(self, pid):
        """Dump the process requested by the user using the pslist plugin"""
        context = contexts.Context()
        context.config["plugins.PsList.pid"] = [
            pid,
        ]
        context.config["plugins.PsList.dump"] = True
        constructed = build_context(
            self.evidence,
            context,
            base_config_path,
            PLUGIN_LIST["windows.pslist.PsList"],
        )
        result = DictRenderer().render(constructed.run())
        artefact = {x.translate({32: None}): y for x, y in result[0].items()}
        return artefact["Fileoutput"]

    def memmap_dump(self, pid):
        """Dump the process requested by the user using the memmap plugin"""
        context = contexts.Context()
        context.config["plugins.Memmap.pid"] = int(pid)
        context.config["plugins.Memmap.dump"] = True
        constructed = build_context(
            self.evidence,
            context,
            base_config_path,
            PLUGIN_LIST["windows.memmap.Memmap"],
        )
        result = DictRenderer().render(constructed.run())
        artefact = clean_result(result)
        return artefact["Fileoutput"]

class DeviceTree(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_devicetree_evidence"
    )
    graph = models.JSONField(null=True)

    @staticmethod
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
                DeviceTree.rename_devicetree(children)

    def run(self):
        context = contexts.Context()
        constructed = build_context(
            self.evidence,
            context,
            base_config_path,
            PLUGIN_LIST["windows.devicetree.DeviceTree"],
        )
        if constructed:
            result = DictRenderer().render(constructed.run())
            for tree in result:
                self.rename_devicetree(tree)
            self.graph = json.dumps(result)


class NetGraph(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_netgraph_evidence"
    )
    graph = models.JSONField(null=True)


class TimeLineChart(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_timeline_evidence"
    )
    graph = models.JSONField(null=True)


class PsScan(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_psscan_evidence"
    )
    PID = models.BigIntegerField(null=True)
    PPID = models.BigIntegerField(null=True)
    ImageFileName = models.TextField(null=True)
    Offset = models.TextField(null=True)
    Threads = models.BigIntegerField(null=True)
    Handles = models.BigIntegerField(null=True)
    SessionId = models.TextField(null=True)
    Wow64 = models.BooleanField()
    CreateTime = models.TextField(null=True)
    ExitTime = models.TextField(null=True)
    Fileoutput = models.TextField(null=True)

    def run(self):
        context = contexts.Context()
        constructed = build_context(
            self.evidence,
            context,
            base_config_path,
            PLUGIN_LIST["windows.psscan.PsScan"],
        )
        if constructed:
            result = DictRenderer().render(constructed.run())
            clean_result(result)
            for key, value in result.items():
                setattr(self, key, value)


class CmdLine(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_cmdline_evidence"
    )
    PID = models.BigIntegerField(null=True)
    Process = models.TextField(null=True)
    Args = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)

    def run(self):
        context = contexts.Context()
        constructed = build_context(
            self.evidence,
            context,
            base_config_path,
            PLUGIN_LIST["windows.cmdline.CmdLine"],
        )
        if constructed:
            result = DictRenderer().render(constructed.run())
            clean_result(result)
            for key, value in result.items():
                setattr(self, key, value)


class Privs(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_privs_evidence"
    )
    PID = models.BigIntegerField(null=True)
    Process = models.TextField(null=True)
    Value = models.TextField(null=True)
    Privilege = models.TextField(null=True)
    Attributes = models.TextField(null=True)
    Description = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)

    def run(self):
        context = contexts.Context()
        constructed = build_context(
            self.evidence,
            context,
            base_config_path,
            PLUGIN_LIST["windows.privileges.Privs"],
        )
        if constructed:
            result = DictRenderer().render(constructed.run())
            clean_result(result)
            for key, value in result.items():
                setattr(self, key, value)


class Sessions(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_sessions_evidence"
    )
    CreateTime = models.TextField(null=True)
    Process = models.TextField(null=True)
    ProcessID = models.BigIntegerField(null=True)
    SessionID = models.BigIntegerField(null=True)
    SessionType = models.TextField(null=True)
    UserName = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)

    def run(self):
        context = contexts.Context()
        constructed = build_context(
            self.evidence,
            context,
            base_config_path,
            PLUGIN_LIST["windows.sessions.Sessions"],
        )
        if constructed:
            result = DictRenderer().render(constructed.run())
            clean_result(result)
            for key, value in result.items():
                setattr(self, key, value)


class GetSIDs(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_getsids_evidence"
    )
    Name = models.TextField(null=True)
    PID = models.BigIntegerField(null=True)
    Process = models.TextField(null=True)
    SID = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)

    def run(self):
        context = contexts.Context()
        constructed = build_context(
            self.evidence,
            context,
            base_config_path,
            PLUGIN_LIST["windows.getsids.GetSIDs"],
        )
        if constructed:
            result = DictRenderer().render(constructed.run())
            clean_result(result)
            for key, value in result.items():
                setattr(self, key, value)


class LdrModules(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_ldrmodules_evidence"
    )
    Base = models.TextField(null=True)
    InInit = models.TextField(null=True)
    InLoad = models.TextField(null=True)
    InMem = models.TextField(null=True)
    MappedPath = models.TextField(null=True)
    Pid = models.BigIntegerField(null=True)
    Process = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)

    def run(self):
        context = contexts.Context()
        constructed = build_context(
            self.evidence,
            context,
            base_config_path,
            PLUGIN_LIST["windows.ldrmodules.LdrModules"],
        )
        if constructed:
            result = DictRenderer().render(constructed.run())
            clean_result(result)
            for key, value in result.items():
                setattr(self, key, value)


class Modules(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_modules_evidence"
    )
    Base = models.TextField(null=True)
    Fileoutput = models.TextField(null=True)
    Name = models.TextField(null=True)
    Offset = models.TextField(null=True)
    Path = models.TextField(null=True)
    Size = models.BigIntegerField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)

    def run(self):
        context = contexts.Context()
        constructed = build_context(
            self.evidence,
            context,
            base_config_path,
            PLUGIN_LIST["windows.modules.Modules"],
        )
        if constructed:
            result = DictRenderer().render(constructed.run())
            clean_result(result)
            for key, value in result.items():
                setattr(self, key, value)


class SvcScan(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_svcscan_evidence"
    )
    Binary = models.TextField(null=True)
    Display = models.TextField(null=True)
    Name = models.TextField(null=True)
    Offset = models.TextField(null=True)
    Order = models.TextField(null=True)
    PID = models.BigIntegerField(null=True)
    Start = models.TextField(null=True)
    State = models.TextField(null=True)
    Type = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)

    def run(self):
        context = contexts.Context()
        constructed = build_context(
            self.evidence,
            context,
            base_config_path,
            PLUGIN_LIST["windows.svcscan.SvcScan"],
        )
        if constructed:
            result = DictRenderer().render(constructed.run())
            clean_result(result)
            for key, value in result.items():
                setattr(self, key, value)


class Envars(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_envars_evidence"
    )
    PID = models.BigIntegerField(null=True)
    Process = models.TextField(null=True)
    Block = models.TextField(null=True)
    Variable = models.TextField(null=True)
    Value = models.TextField(null=True)
    Description = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)

    def run(self):
        context = contexts.Context()
        constructed = build_context(
            self.evidence,
            context,
            base_config_path,
            PLUGIN_LIST["windows.envars.Envars"],
        )
        if constructed:
            result = DictRenderer().render(constructed.run())
            clean_result(result)
            for key, value in result.items():
                setattr(self, key, value)


class NetScan(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_netscan_evidence"
    )
    Offset = models.TextField(null=True)
    Proto = models.TextField(null=True)
    LocalAddr = models.TextField(null=True)
    LocalPort = models.TextField(null=True)
    ForeignAddr = models.TextField(null=True)
    ForeignPort = models.TextField(null=True)
    State = models.TextField(null=True)
    PID = models.BigIntegerField(null=True)
    Owner = models.TextField(null=True)
    Created = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)

    def run(self):
        context = contexts.Context()
        constructed = build_context(
            self.evidence,
            context,
            base_config_path,
            PLUGIN_LIST["windows.netscan.NetScan"],
        )
        if constructed:
            result = DictRenderer().render(constructed.run())
            clean_result(result)
            for key, value in result.items():
                setattr(self, key, value)


class NetStat(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_netstat_evidence"
    )
    Offset = models.TextField(null=True)
    Proto = models.TextField(null=True)
    LocalAddr = models.TextField(null=True)
    LocalPort = models.TextField(null=True)
    ForeignAddr = models.TextField(null=True)
    ForeignPort = models.TextField(null=True)
    State = models.TextField(null=True)
    PID = models.BigIntegerField(null=True)
    Owner = models.TextField(null=True)
    Created = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)

    def run(self):
        context = contexts.Context()
        constructed = build_context(
            self.evidence,
            context,
            base_config_path,
            PLUGIN_LIST["windows.netstat.NetStat"],
        )
        if constructed:
            result = DictRenderer().render(constructed.run())
            clean_result(result)
            for key, value in result.items():
                setattr(self, key, value)


class Hashdump(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_hashdump_evidence"
    )
    User = models.TextField(null=True)
    rid = models.TextField(null=True)
    lmhash = models.TextField(null=True)
    nthash = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)

    def run(self):
        context = contexts.Context()
        constructed = build_context(
            self.evidence,
            context,
            base_config_path,
            PLUGIN_LIST["windows.hashdump.Hashdump"],
        )
        if constructed:
            result = DictRenderer().render(constructed.run())
            clean_result(result)
            for key, value in result.items():
                setattr(self, key, value)


class Lsadump(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_lsadump_evidence"
    )
    Key = models.TextField(null=True)
    Secret = models.TextField(null=True)
    Hex = models.TextField(null=True)

    def save(self, *args, **kwargs):
        self.Secret = base64.b64encode(bytes(self.Secret, "utf-8"))
        super().save(*args, **kwargs)

    def run(self):
        context = contexts.Context()
        constructed = build_context(
            self.evidence,
            context,
            base_config_path,
            PLUGIN_LIST["windows.lsadump.Lsadump"],
        )
        if constructed:
            result = DictRenderer().render(constructed.run())
            clean_result(result)
            for key, value in result.items():
                setattr(self, key, value)


class Cachedump(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_cachedump_evidence"
    )
    Domain = models.TextField(null=True)
    Domainname = models.TextField(null=True)
    Hash = models.TextField(null=True)
    Username = models.TextField(null=True)

    def run(self):
        context = contexts.Context()
        constructed = build_context(
            self.evidence,
            context,
            base_config_path,
            PLUGIN_LIST["windows.cachedump.Cachedump"],
        )
        if constructed:
            result = DictRenderer().render(constructed.run())
            clean_result(result)
            for key, value in result.items():
                setattr(self, key, value)


class HiveList(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_hivelist_evidence"
    )
    FileFullPath = models.TextField(null=True)
    Offset = models.TextField(null=True)
    Fileoutput = models.TextField(null=True)

    def run(self):
        context = contexts.Context()
        context.config["plugins.HiveList.dump"] = True
        constructed = build_context(
            self.evidence,
            context,
            base_config_path,
            PLUGIN_LIST["windows.registry.hivelist.HiveList"],
        )
        if constructed:
            result = DictRenderer().render(constructed.run())
            clean_result(result)
            for key, value in result.items():
                setattr(self, key, value)


class Timeliner(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_timeliner_evidence"
    )
    Plugin = models.TextField(null=True)
    Description = models.TextField(null=True)
    AccessedDate = models.TextField(null=True)
    ChangedDate = models.TextField(null=True)
    CreatedDate = models.TextField(null=True)
    ModifiedDate = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)

    def run(self):
        context = contexts.Context()
        constructed = build_context(
            self.evidence,
            context,
            base_config_path,
            PLUGIN_LIST["timeliner.Timeliner"],
        )
        if constructed:
            result = DictRenderer().render(constructed.run())
            clean_result(result)
            for key, value in result.items():
                setattr(self, key, value)


class SkeletonKeyCheck(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_skc_evidence"
    )
    PID = models.BigIntegerField(null=True)
    Process = models.TextField(null=True)
    SkeletonKeyFound = models.TextField(null=True)
    rc4HmacInitialize = models.TextField(null=True)
    rc4HmacDecrypt = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)

    def run(self):
        context = contexts.Context()
        constructed = build_context(
            self.evidence,
            context,
            base_config_path,
            PLUGIN_LIST["windows.skeleton_key_check.Skeleton_Key_Check"],
        )
        if constructed:
            result = DictRenderer().render(constructed.run())
            clean_result(result)
            for key, value in result.items():
                setattr(self, key, value)


class Malfind(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_malfind_evidence"
    )

    PID = models.BigIntegerField(null=True)
    Process = models.TextField(null=True)
    StartVPN = models.TextField(null=True)
    EndVPN = models.TextField(null=True)
    VTag = models.TextField(null=True)
    Protection = models.TextField(null=True)
    CommitCharge = models.TextField(null=True)
    PrivateMemory = models.TextField(null=True)
    Fileoutput = models.TextField(null=True)
    Hexdump = models.TextField(null=True)
    Disasm = models.TextField(null=True)

    def run(self):
        context = contexts.Context()
        constructed = build_context(
            self.evidence,
            context,
            base_config_path,
            PLUGIN_LIST["windows.malfind.Malfind"],
        )
        if constructed:
            result = DictRenderer().render(constructed.run())
            clean_result(result)
            for key, value in result.items():
                setattr(self, key, value)


class UserAssist(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_userassist_evidence"
    )
    HiveOffset = models.TextField(null=True)
    HiveName = models.TextField(null=True)
    Path = models.TextField(null=True)
    LastWriteTime = models.TextField(null=True)
    Type = models.TextField(null=True)
    Name = models.TextField(null=True)
    ID = models.TextField(null=True)
    Count = models.TextField(null=True)
    FocusCount = models.TextField(null=True)
    TimeFocused = models.TextField(null=True)
    LastUpdated = models.TextField(null=True)
    RawData = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)

    def fill_userassist(list, self):
        for artefact in list:
            UserAssist(
                evidence=self.evidence.dump_id,
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
                self.fill_userassist(artefact["__children"])

    def run(self):
        context = contexts.Context()
        constructed = build_context(
            self.evidence,
            context,
            base_config_path,
            PLUGIN_LIST["windows.registry.userassist.UserAssist"],
        )
        if constructed:
            result = DictRenderer().render(constructed.run())
            self.fill_userassist(result)
            for key, value in result.items():
                setattr(self, key, value)


class FileScan(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_filescan_evidence"
    )
    Offset = models.TextField(null=True)
    Name = models.TextField(null=True)
    Size = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)

    def run(self):
        context = contexts.Context()
        constructed = build_context(
            self.evidence,
            context,
            base_config_path,
            PLUGIN_LIST["windows.filescan.FileScan"],
        )
        if constructed:
            result = DictRenderer().render(constructed.run())
            clean_result(result)
            for key, value in result.items():
                setattr(self, key, value)


class Strings(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_strings_evidence"
    )
    String = models.TextField(null=True)
    PhysicalAddress = models.TextField(null=True)
    Result = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)


class DllList(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_dllist_evidence"
    )
    Process = models.TextField(null=True)
    PID = models.BigIntegerField(null=True)
    Base = models.TextField(null=True)
    Name = models.TextField(null=True)
    Path = models.TextField(null=True)
    Size = models.TextField(null=True)
    LoadTime = models.TextField(null=True)
    Fileoutput = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)

    def run(self):
        context = contexts.Context()
        constructed = build_context(
            self.evidence,
            context,
            base_config_path,
            PLUGIN_LIST["windows.dlllist.DllList"],
        )
        if constructed:
            result = DictRenderer().render(constructed.run())
            clean_result(result)
            for key, value in result.items():
                setattr(self, key, value)


class Handles(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_handles_evidence"
    )
    Process = models.TextField(null=True)
    PID = models.BigIntegerField()
    Offset = models.TextField(null=True)
    Name = models.TextField(null=True)
    HandleValue = models.IntegerField(null=True)
    GrantedAccess = models.TextField(null=True)
    Type = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)

    def run(self):
        context = contexts.Context()
        constructed = build_context(
            self.evidence,
            context,
            base_config_path,
            PLUGIN_LIST["windows.handles.Handles"],
        )
        if constructed:
            result = DictRenderer().render(constructed.run())
            clean_result(result)
            for key, value in result.items():
                setattr(self, key, value)

    def get_handles(self, pid):
        """Compute Handles for a specific PID"""
        context = contexts.Context()
        context.config["plugins.Handles.pid"] = [int(pid)]
        try:
            constructed = build_context(
                self.evidence,
                context,
                base_config_path,
                PLUGIN_LIST["windows.handles.Handles"],
            )
            result = DictRenderer().render(constructed.run())
            for artefact in result:
                artefact = {x.translate({32: None}): y for x, y in artefact.items()}
                del artefact["__children"]
                Handles(evidence=self.evidence, **artefact).save()
            return 0
        except:
            return -1



class DriverModule(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_drivermodule_evidence"
    )
    AlternativeName = models.TextField(null=True)
    DriverName = models.TextField(null=True)
    KnownException = models.TextField(null=True)
    Offset = models.TextField(null=True)
    ServiceKey = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)

    def run(self):
        context = contexts.Context()
        constructed = build_context(
            self.evidence,
            context,
            base_config_path,
            PLUGIN_LIST["windows.drivermodule.DriverModule"],
        )
        if constructed:
            result = DictRenderer().render(constructed.run())
            clean_result(result)
            for key, value in result.items():
                setattr(self, key, value)


class VadWalk(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_vadwalk_evidence"
    )
    End = models.TextField(null=True)
    Left = models.TextField(null=True)
    Offset = models.TextField(null=True)
    PID = models.BigIntegerField()
    Parent = models.TextField(null=True)
    Process = models.TextField(null=True)
    Right = models.TextField(null=True)
    Start = models.TextField(null=True)
    VTag = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)

    def run(self):
        context = contexts.Context()
        constructed = build_context(
            self.evidence,
            context,
            base_config_path,
            PLUGIN_LIST["windows.vadwalk.VadWalk"],
        )
        if constructed:
            result = DictRenderer().render(constructed.run())
            clean_result(result)
            for key, value in result.items():
                setattr(self, key, value)


class SSDT(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_ssdt_evidence"
    )
    Address = models.TextField(null=True)
    Index = models.BigIntegerField(null=True)
    Module = models.TextField(null=True)
    Symbol = models.TextField(null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS)

    def run(self):
        context = contexts.Context()
        constructed = build_context(
            self.evidence,
            context,
            base_config_path,
            PLUGIN_LIST["windows.ssdt.SSDT"],
        )
        if constructed:
            result = DictRenderer().render(constructed.run())
            clean_result(result)
            for key, value in result.items():
                setattr(self, key, value)


class Loot(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="windows_loot"
    )
    FileName = models.TextField(null=True)
    Name = models.TextField()
    Status = models.BooleanField()
