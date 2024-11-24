from rest_framework import serializers
from .models import Evidence


class EvidenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Evidence
        fields = "__all__"


class BindEvidenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Evidence
        fields = "__all__"
        extra_kwargs = {
            "access_key_id": {"write_only": True},
            "access_key": {"write_only": True},
            "etag": {"read_only": True},
            "name": {"read_only": True},
        }
