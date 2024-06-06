from rest_framework import serializers
from windows_engine.models import *
from django_celery_results.models import TaskResult


class PsScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = PsScan
        fields = "__all__"


class PsTreeSerializer(serializers.ModelSerializer):
    class Meta:
        model = PsTree
        fields = "__all__"


class TimelineChartSerializer(serializers.ModelSerializer):
    class Meta:
        model = TimeLineChart
        fields = "__all__"


class TimelineDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = Timeliner
        fields = "__all__"


class TimelineTagSerializer(serializers.ModelSerializer):
    class Meta:
        model = Timeliner
        fields = ("Tag",)


class CmdLineSerializer(serializers.ModelSerializer):
    class Meta:
        model = CmdLine
        fields = "__all__"


class GetSIDsSerializer(serializers.ModelSerializer):
    class Meta:
        model = GetSIDs
        fields = "__all__"


class PrivsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Privs
        fields = "__all__"


class HiveListSerializer(serializers.ModelSerializer):
    class Meta:
        model = HiveList
        fields = "__all__"


class SvcScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = SvcScan
        fields = "__all__"


class EnvarsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Envars
        fields = "__all__"


class DllListSerializer(serializers.ModelSerializer):
    class Meta:
        model = DllList
        fields = "__all__"


class SessionsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Sessions
        fields = "__all__"


class NetStatSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetStat
        fields = "__all__"


class NetScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetScan
        fields = "__all__"


class NetGraphSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetGraph
        fields = "__all__"


class HashdumpSerializer(serializers.ModelSerializer):
    class Meta:
        model = Hashdump
        fields = "__all__"


class CachedumpSerializer(serializers.ModelSerializer):
    class Meta:
        model = Cachedump
        fields = "__all__"


class LsadumpSerializer(serializers.ModelSerializer):
    class Meta:
        model = Lsadump
        fields = "__all__"


class HandlesSerializer(serializers.ModelSerializer):
    class Meta:
        model = Handles
        fields = "__all__"


class MalfindSerializer(serializers.ModelSerializer):
    class Meta:
        model = Malfind
        fields = "__all__"


class LdrModulesSerializer(serializers.ModelSerializer):
    class Meta:
        model = LdrModules
        fields = "__all__"


class ModulesSerializer(serializers.ModelSerializer):
    class Meta:
        model = Modules
        fields = "__all__"


class SSDTSerializer(serializers.ModelSerializer):
    class Meta:
        model = SSDT
        fields = "__all__"

class ThrdScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = ThrdScan
        fields = "__all__"

class DriverIrpSerializer(serializers.ModelSerializer):
    class Meta:
        model = DriverIrp
        fields = "__all__"

class IATSerializer(serializers.ModelSerializer):
    class Meta:
        model = IAT
        fields = "__all__"

class FileScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = FileScan
        fields = "__all__"


class MFTScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = MFTScan
        fields = "__all__"


class MBRScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = MBRScan
        fields = "__all__"


class ADSSerializer(serializers.ModelSerializer):
    class Meta:
        model = ADS
        fields = "__all__"


class TasksSerializer(serializers.ModelSerializer):
    task_kwargs = serializers.JSONField

    class Meta:
        model = TaskResult
        fields = "__all__"

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        # We have to do this because the json is not respecting the rfc.
        ret["task_kwargs"] = ret["task_kwargs"].replace("'", '"')
        return ret


class LootSerializer(serializers.ModelSerializer):
    class Meta:
        model = Loot
        fields = "__all__"
