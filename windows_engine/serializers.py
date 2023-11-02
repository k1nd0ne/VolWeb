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

class GetSIDsSerializer(serializers.ModelSerializer):
    class Meta:
        model = GetSIDs
        fields = '__all__'

class PrivsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Privs
        fields = '__all__'

class EnvarsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Envars
        fields = '__all__'

class DllListSerializer(serializers.ModelSerializer):
    class Meta:
        model = DllList
        fields = '__all__'

class SessionsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Sessions
        fields = '__all__'