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
from urllib.parse import urlparse, urlunparse
import boto3
from botocore.client import Config

def get_s3_client():
    s3_client = boto3.client(
        's3',
        endpoint_url=f'http://{CloudStorage.AWS_ENDPOINT_HOST}',
        aws_access_key_id=CloudStorage.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=CloudStorage.AWS_SECRET_ACCESS_KEY,
        config=Config(signature_version='s3v4'),
    )
    return s3_client

class CaseViewSet(viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated,)
    queryset = Case.objects.all()
    serializer_class = CaseSerializer

    def create(self, request, *args, **kwargs):
        bucket_uuid = f"volweb-{str(uuid.uuid4())}"
        try:
            client = Minio(
                CloudStorage.AWS_ENDPOINT_HOST,
                CloudStorage.AWS_ACCESS_KEY_ID,
                CloudStorage.AWS_SECRET_ACCESS_KEY,
                secure=False,
            )
            client.make_bucket(bucket_uuid)
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
            secure=False,
        )

        url = client.presigned_put_object(
            bucket_name=str(case.bucket_id),
            object_name=filename,
            expires=timedelta(hours=1),
        )

        return Response({"url": url})


class CompleteMultipartUploadView(APIView):
    def post(self, request, case_id):
        filename = request.data.get("filename")
        upload_id = request.data.get("upload_id")
        parts = request.data.get("parts")  # Should be a list of dicts with 'ETag' and 'PartNumber'

        case = get_object_or_404(Case, id=case_id)

        s3_client = get_s3_client()

        # Ensure PartNumber is int and ETag is str
        multipart_upload = {'Parts': [{'ETag': p['ETag'], 'PartNumber': int(p['PartNumber'])} for p in parts]}

        try:
            response = s3_client.complete_multipart_upload(
                Bucket=str(case.bucket_id),
                Key=filename,
                UploadId=upload_id,
                MultipartUpload=multipart_upload,
            )
        except Exception as err:
            return Response(
                {"error": "Could not complete multipart upload", "details": str(err)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response({"result": "Upload completed", "location": response.get('Location')}, status=status.HTTP_200_OK)


class GeneratePresignedUrlForPartView(APIView):
    def get(self, request, case_id):
        filename = request.query_params.get("filename")
        part_number = int(request.query_params.get("part_number"))
        upload_id = request.query_params.get("upload_id")

        case = get_object_or_404(Case, id=case_id)

        s3_client = get_s3_client()

        try:
            presigned_url = s3_client.generate_presigned_url(
                'upload_part',
                Params={
                    'Bucket': str(case.bucket_id),
                    'Key': filename,
                    'UploadId': upload_id,
                    'PartNumber': part_number,
                },
                ExpiresIn=3600,
                HttpMethod='PUT',
            )
        except Exception as err:
            return Response(
                {"error": "Could not generate presigned URL", "details": str(err)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response({"url": presigned_url}, status=status.HTTP_200_OK)


class InitiateMultipartUploadView(APIView):
    def post(self, request, case_id):
        filename = request.data.get("filename")
        case = get_object_or_404(Case, id=case_id)

        s3_client = get_s3_client()
        try:
            response = s3_client.create_multipart_upload(
                Bucket=str(case.bucket_id),
                Key=filename,
            )
            upload_id = response['UploadId']
        except Exception as err:
            return Response(
                {"error": "Could not initiate multipart upload", "details": str(err)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response({"upload_id": upload_id}, status=status.HTTP_200_OK)
