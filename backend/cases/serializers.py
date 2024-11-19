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
