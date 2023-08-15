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
    
    def create(self, validated_data):
        linked_users_data = validated_data.pop('linked_users')  # Extract linked_users data

        case = Case.objects.create(**validated_data)  # Create Case instance

        for user_data in linked_users_data:
            uid = user_data['username']
            user = User.objects.get(pk=uid)
            case.linked_users.add(user)
        
        return case