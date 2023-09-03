from rest_framework import serializers
from windows_engine.models import PsTree

class PsTreeSerializer(serializers.ModelSerializer):
    class Meta:
        model = PsTree
        fields = '__all__'