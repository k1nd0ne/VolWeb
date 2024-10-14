from rest_framework import serializers
from .models import VolatilityPlugin


class VolatilityPluginNameSerializer(serializers.ModelSerializer):
    class Meta:
        model = VolatilityPlugin
        fields = ["name", "description", "icon"]


class VolatilityPluginDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = VolatilityPlugin
        fields = ["name", "artefacts"]
