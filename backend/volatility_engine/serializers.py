from rest_framework import serializers
from .models import VolatilityPlugin


class VolatilityPluginNameSerializer(serializers.ModelSerializer):
    class Meta:
        model = VolatilityPlugin
        fields = ["name"]


class VolatilityPluginDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = VolatilityPlugin
        fields = ["name", "artefacts"]
