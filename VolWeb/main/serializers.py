from rest_framework import serializers
from main.models import Case
from django.contrib.auth.models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username']

class CaseSerializer(serializers.ModelSerializer):
    linked_users = UserSerializer(many=True)

    class Meta:
        model = Case
        fields = ['case_id', 'case_name', 'case_description', 'linked_users', 'case_last_update']