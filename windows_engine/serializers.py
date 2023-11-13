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


class TimelineTagSerializer(serializers.ModelSerializer):
    class Meta:
        model = Timeliner
        fields = ('Tag',)

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


class NetStatSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetStat
        fields = '__all__'

class NetScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetScan
        fields = '__all__'

class NetGraphSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetGraph
        fields = '__all__'

class HashdumpSerializer(serializers.ModelSerializer):
    class Meta:
        model = Hashdump
        fields = '__all__'

class CachedumpSerializer(serializers.ModelSerializer):
    class Meta:
        model = Cachedump
        fields = '__all__'

class LsadumpSerializer(serializers.ModelSerializer):
    class Meta:
        model = Lsadump
        fields = '__all__'

class HandlesSerializer(serializers.ModelSerializer):
    class Meta:
        model = Handles
        fields = '__all__'