from rest_framework import viewsets, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .models import Case
from .serializers import CaseSerializer
from minio import Minio
from backend.keyconfig import CloudStorage
from django.conf import settings
import uuid

class CaseViewSet(viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated, )
    queryset = Case.objects.all()
    serializer_class = CaseSerializer

    def create(self, request, *args, **kwargs):
        bucket_uuid = uuid.uuid4()
        try:
            client = Minio(
                CloudStorage.AWS_ENDPOINT_HOST,
                CloudStorage.AWS_ACCESS_KEY_ID,
                CloudStorage.AWS_SECRET_ACCESS_KEY,
                secure=(not settings.DEBUG),
            )
            client.make_bucket(str(bucket_uuid))
        except Exception as e:
            print(e)
            return Response(
                {"error": "The bucket could not be created", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        print(request.data)
        data = {
            "name": request.data.get("name"),
            "description": request.data.get("description"),
            "linked_users": request.data.get("linked_users"),
            "bucket_id": bucket_uuid,
        }

        serializer = CaseSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            print(serializer.errors)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
