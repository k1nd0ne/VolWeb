from django.contrib.auth.models import User
from rest_framework import serializers
from .models import Indicator
from django_celery_results.models import TaskResult


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "username", "email", "first_name", "last_name")

class IndicatorSerializer(serializers.ModelSerializer):
    dump_linked_dump_name = serializers.SerializerMethodField()

    class Meta:
        model = Indicator
        fields = "__all__"
        extra_fields = ["dump_linked_dump_name"]

    def get_dump_linked_dump_name(self, obj):
        # Return the name of the linked case instead of the id
        return obj.evidence.name


class TypeSerializer(serializers.Serializer):
    value = serializers.CharField()
    display = serializers.CharField()

class TasksSerializer(serializers.ModelSerializer):
    task_kwargs = serializers.JSONField

    class Meta:
        model = TaskResult
        fields = "__all__"
