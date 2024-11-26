from rest_framework import serializers
from .models import Case
from django.contrib.auth.models import User


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["username", "id"]


class CaseSerializer(serializers.ModelSerializer):
    linked_users = UserSerializer(many=True)

    class Meta:
        model = Case
        fields = "__all__"


class InitiateUploadSerializer(serializers.Serializer):
    filename = serializers.CharField(max_length=255)
    os = serializers.CharField(max_length=255)
    case_id = serializers.IntegerField()


class UploadChunkSerializer(serializers.Serializer):
    upload_id = serializers.UUIDField()
    part_number = serializers.IntegerField()
    chunk = serializers.FileField()


class CompleteUploadSerializer(serializers.Serializer):
    upload_id = serializers.UUIDField()
