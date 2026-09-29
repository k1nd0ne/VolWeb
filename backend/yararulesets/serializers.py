# yararuleset/serializers.py
from rest_framework import serializers
from .models import YaraRuleSet
from yararules.models import YaraRule
from core.validators import validate_upload_filename


class YaraRuleSetSerializer(serializers.ModelSerializer):
    rules = serializers.SerializerMethodField()

    class Meta:
        model = YaraRuleSet
        fields = '__all__'
        read_only_fields = ('created_at', 'updated_at')

    def get_rules(self, obj):
        try:
            qs = YaraRule.objects.filter(linked_yararuleset=obj, is_active=True, status=100).values_list('id', flat=True)
            return list(qs)
        except Exception:
            return []
        
        
class InitiateUploadSerializer(serializers.Serializer):
    filename = serializers.CharField(
        max_length=255, validators=[validate_upload_filename]
    )
    description = serializers.CharField(max_length=255,required=False, allow_blank=True, default="")
    yara_ruleset_id = serializers.IntegerField(required=False, allow_null=True, default=None)
    source = serializers.CharField(max_length=255)

class UploadChunkSerializer(serializers.Serializer):
    upload_id = serializers.UUIDField()
    part_number = serializers.IntegerField()
    chunk = serializers.FileField()


class CompleteUploadSerializer(serializers.Serializer):
    upload_id = serializers.UUIDField()
