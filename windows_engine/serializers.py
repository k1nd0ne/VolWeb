from rest_framework import serializers
from windows_engine.models import *

class PsTreeSerializer(serializers.ModelSerializer):
    class Meta:
        model = PsTree
        fields = '__all__'

class TimelineChartSerializer(serializers.ModelSerializer):
    class Meta:
        model = TimeLineChart
        fields = '__all__'

class TimelineDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = Timeliner
        fields = '__all__'

class CmdLineSerializer(serializers.ModelSerializer):
    class Meta:
        model = CmdLine
        fields = '__all__'