from rest_framework import serializers
from cases.models import Case
from django.contrib.auth.models import User
from django.dispatch import receiver
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from django.db.models.signals import post_save, post_delete

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["username", "id"]


class CaseSerializer(serializers.ModelSerializer):
    linked_users = UserSerializer(many=True)

    class Meta:
        model = Case
        fields = "__all__"

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
                )

        instance.save()  # Save the updated instance

        return instance

@receiver(post_save, sender=Case)
def send_case_created(sender, instance, created, **kwargs):
    channel_layer = get_channel_layer()
    serializer = CaseSerializer(instance)
    async_to_sync(channel_layer.group_send)(
        "cases",
        {
            "type": "send_notification",
            "status": "created",
            "message": serializer.data
        }
    )

@receiver(post_delete, sender=Case,)
def send_case_created(sender, instance, **kwargs):
    channel_layer = get_channel_layer()
    serializer = CaseSerializer(instance)
    print(serializer)
    async_to_sync(channel_layer.group_send)(
        "cases",
        {
            "type": "send_notification",
            "status": "deleted",
            "message": serializer.data
        }
    )