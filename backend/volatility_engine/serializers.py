from rest_framework import serializers
from .models import VolatilityPlugin, EnrichedProcess
from django_celery_results.models import TaskResult


class VolatilityPluginNameSerializer(serializers.ModelSerializer):
    class Meta:
        model = VolatilityPlugin
        fields = ["name", "description", "icon", "category", "display", "results"]


class VolatilityPluginDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = VolatilityPlugin
        fields = ["name", "artefacts"]


class TasksSerializer(serializers.ModelSerializer):
    task_kwargs = serializers.JSONField

    class Meta:
        model = TaskResult
        fields = "__all__"


class EnrichedProcessSerializer(serializers.ModelSerializer):
    class Meta:
        model = EnrichedProcess
        fields = "__all__"
