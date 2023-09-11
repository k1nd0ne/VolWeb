from rest_framework import serializers
from windows_engine.models import PsTree, TimeLineChart, Timeliner

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