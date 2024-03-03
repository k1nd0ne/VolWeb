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

class PsScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = PsScan
        fields = "__all__"

class BashSerializer(serializers.ModelSerializer):
    class Meta:
        model = Bash
        fields = "__all__"

class ElfsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Elfs
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
