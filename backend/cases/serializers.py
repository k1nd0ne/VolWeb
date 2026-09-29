from rest_framework import serializers
from .models import Case
from django.contrib.auth.models import User
from core.serializers import UserSerializer
from core.validators import validate_upload_filename

    # class UserSerializer(serializers.ModelSerializer):
    #     class Meta:
    #         model = User
    #         fields = ["username", "id"]


class CaseSerializer(serializers.ModelSerializer):
    linked_users = UserSerializer(many=True)

    class Meta:
        model = Case
        fields = "__all__"


class InitiateUploadSerializer(serializers.Serializer):
    filename = serializers.CharField(
        max_length=255, validators=[validate_upload_filename]
    )
    os = serializers.CharField(max_length=255)
    case_id = serializers.IntegerField()


class UploadChunkSerializer(serializers.Serializer):
    upload_id = serializers.UUIDField()
    part_number = serializers.IntegerField()
    chunk = serializers.FileField()


class CompleteUploadSerializer(serializers.Serializer):
    upload_id = serializers.UUIDField()
