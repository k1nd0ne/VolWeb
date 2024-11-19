from rest_framework import viewsets, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from datetime import timedelta
from minio import Minio
from django.shortcuts import get_object_or_404
from backend.keyconfig import CloudStorage
from django.conf import settings
from .models import Case
from .serializers import CaseSerializer
import uuid


class CaseViewSet(viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated,)
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
            return Response(
                {"error": "The bucket could not be created", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        # Extract direct fields
        name = request.data.get("name")
        description = request.data.get("description")
        linked_users_ids = request.data.get("linked_users", [])

        # Create the case instance with direct fields
        case = Case(name=name, description=description, bucket_id=bucket_uuid)
        case.save()

        # Add linked users
        for user_id in linked_users_ids:
            case.linked_users.add(user_id)

        case.save()

        serializer = CaseSerializer(case)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class GeneratePresignedUrlView(APIView):
    def get(self, request, case_id):
        filename = request.query_params.get("filename")
        case = get_object_or_404(Case, id=case_id)
        client = Minio(
            endpoint=CloudStorage.AWS_ENDPOINT_HOST,
            access_key=CloudStorage.AWS_ACCESS_KEY_ID,
            secret_key=CloudStorage.AWS_SECRET_ACCESS_KEY,
            secure=(not settings.DEBUG),
        )
        url = client.presigned_put_object(
            bucket_name=str(case.bucket_id),
            object_name=filename,
            expires=timedelta(hours=1),
        )
        return Response({"url": url})
