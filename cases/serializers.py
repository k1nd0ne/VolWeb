from rest_framework import serializers
from cases.models import Case
from django.contrib.auth.models import User


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["username", "id"]


class CaseSerializer(serializers.ModelSerializer):
    linked_users = UserSerializer(many=True)

    class Meta:
        model = Case
        fields = [
            "case_id",
            "case_bucket_id",
            "case_name",
            "case_description",
            "linked_users",
            "case_last_update",
        ]

    def create(self, validated_data):
        linked_users_data = validated_data.pop(
            "linked_users"
        )  # Extract linked_users data
        case = Case.objects.create(**validated_data)  # Create Case instance

        for user_data in linked_users_data:
            uid = user_data["username"]
            user = User.objects.get(pk=uid)
            case.linked_users.add(user)

        return case

    def update(self, instance, validated_data):
        linked_users_data = validated_data.pop(
            "linked_users", None
        )  # Extract linked_users data

        # Update the instance fields with the validated data
        instance.case_name = validated_data.get("case_name", instance.case_name)
        instance.case_description = validated_data.get(
            "case_description", instance.case_description
        )

        if linked_users_data:
            instance.linked_users.clear()  # Remove existing linked_users

            for user_data in linked_users_data:
                username = user_data["username"]
                user = User.objects.get(pk=username)
                instance.linked_users.add(
                    user
                )  # Assuming linked_users is a ManyToManyField in Case model

        instance.save()  # Save the updated instance

        return instance
