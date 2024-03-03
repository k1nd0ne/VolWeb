from django.db import models
from evidences.models import Evidence
import base64
from celery import shared_task
import logging, json
import volatility3
from volatility3.framework import contexts
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

class PsTree(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="linux_pstree_evidence"
    )
    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="Linux.PsTree.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["linux.pstree.PsTree"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None

class PsAux(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="linux_psaux_evidence"
    )
    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="Linux.PsAux.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["linux.psaux.PsAux"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None

class Lsof(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="linux_lsof_evidence"
    )
    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="Linux.Lsof.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["linux.lsof.Lsof"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None

class PsScan(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="linux_psscan_evidence"
    )
    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="Linux.PsScan.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["linux.psscan.PsScan"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None

class Bash(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="linux_bash_evidence"
    )
    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="Linux.Bash.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["linux.bash.Bash"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None

class Elfs(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="linux_elfs_evidence"
    )
    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="Linux.Elfs.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["linux.elfs.Elfs"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None

class Sockstat(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="linux_sockstat_evidence"
    )
    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="Linux.Sockstat.run")
    def run(evidence_data):
        try:
            context = contexts.Context()
            constructed = build_context(
                evidence_data,
                context,
                base_config_path,
                PLUGIN_LIST["linux.sockstat.Sockstat"],
            )
            if constructed:
                result = DictRenderer().render(constructed.run())
                return result
        except:
            return None

class NetGraph(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="linux_netgraph_evidence"
    )
    artefacts = models.JSONField(null=True)

class TimeLineChart(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="linux_timeline_evidence"
    )
    artefacts = models.JSONField(null=True)

class Timeliner(models.Model):
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE, related_name="linux_timeliner_evidence"
    )

    artefacts = models.JSONField(null=True)

    @staticmethod
    @shared_task(name="Linux.Timeliner.run")
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
