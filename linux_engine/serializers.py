from rest_framework import serializers
from linux_engine.models import *
from django_celery_results.models import TaskResult

class PsTreeSerializer(serializers.ModelSerializer):
    class Meta:
        model = PsTree
        fields = "__all__"

class PsAuxSerializer(serializers.ModelSerializer):
    class Meta:
        model = PsAux
        fields = "__all__"

class LsofSerializer(serializers.ModelSerializer):
    class Meta:
        model = Lsof
        fields = "__all__"

class EnvarsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Envars
        fields = "__all__"

class PsScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = PsScan
        fields = "__all__"

class MountInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = MountInfo
        fields = "__all__"

class tty_checkSerializer(serializers.ModelSerializer):
    class Meta:
        model = tty_check
        fields = "__all__"

class BashSerializer(serializers.ModelSerializer):
    class Meta:
        model = Bash
        fields = "__all__"

class ElfsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Elfs
        fields = "__all__"

class MalfindSerializer(serializers.ModelSerializer):
    class Meta:
        model = Malfind
        fields = "__all__"

class LsmodSerializer(serializers.ModelSerializer):
    class Meta:
        model = Lsmod
        fields = "__all__"

class CapabilitiesSerializer(serializers.ModelSerializer):
    class Meta:
        model = Capabilities
        fields = "__all__"

class KmsgSerializer(serializers.ModelSerializer):
    class Meta:
        model = Kmsg
        fields = "__all__"

class NetGraphSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetGraph
        fields = "__all__"

class TimelineChartSerializer(serializers.ModelSerializer):
    class Meta:
        model = TimeLineChart
        fields = "__all__"


class TimelineDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = Timeliner
        fields = "__all__"
