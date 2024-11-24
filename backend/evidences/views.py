from rest_framework import viewsets
from rest_framework.views import APIView
from .models import Evidence
from .serializers import EvidenceSerializer, BindEvidenceSerializer
from rest_framework.permissions import IsAuthenticated
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.response import Response
from rest_framework import status
from evidences.models import Evidence
from volatility_engine.models import VolatilityPlugin
from collections import Counter
from urllib.parse import urlparse
import boto3
import botocore
from minio import Minio


class EvidenceViewSet(viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated,)
    queryset = Evidence.objects.all()
    serializer_class = EvidenceSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["linked_case"]


class EvidenceStatisticsApiView(APIView):
    """
    API view to get statistics about an evidence.
    """

    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        evidence_id = kwargs.get("id")
        if not evidence_id:
            return Response(
                {"error": "Evidence ID is required"}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            evidence = Evidence.objects.get(id=evidence_id)
        except Evidence.DoesNotExist:
            return Response(
                {"error": "Evidence with specified ID does not exist"},
                status=status.HTTP_404_NOT_FOUND,
            )

        plugins = VolatilityPlugin.objects.filter(evidence=evidence).exclude(
            category="Other"
        )

        # Calculate the number of artefacts per plugin category
        category_artefacts_counter = Counter()
        for plugin in plugins:
            if plugin.results:
                artefacts_count = len(plugin.artefacts)
                category_artefacts_counter[plugin.category] += artefacts_count

        total_ran = plugins.count()
        total_results = plugins.filter(results=True).count()

        return Response(
            {
                "categories": dict(category_artefacts_counter),
                "total_ran": total_ran,
                "total_results": total_results,
            },
            status=status.HTTP_200_OK,
        )


class BindEvidenceViewSet(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        data = request.data

        required_fields = [
            "os",
            "linked_case",
            "source",
            "access_key_id",
            "access_key",
            "url",
            "endpoint",
        ]

        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return Response(
                {"detail": f'Missing fields: {", ".join(missing_fields)}.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        os = data["os"]
        linked_case = data["linked_case"]
        source = data["source"]
        access_key_id = data["access_key_id"]
        access_key = data["access_key"]
        url = data["url"]
        region = data.get("region")
        endpoint = data["endpoint"]

        # Parse the URL to get bucket and key
        def parse_s3_url(url):
            parsed_url = urlparse(url)
            if parsed_url.scheme == "s3":
                bucket = parsed_url.netloc
                key = parsed_url.path.lstrip("/")
            elif parsed_url.scheme in ("s3"):
                netloc_parts = parsed_url.netloc.split(".")
                if "s3" in netloc_parts:
                    # URL format: https://bucket.s3.amazonaws.com/key
                    bucket = netloc_parts[0]
                    key = parsed_url.path.lstrip("/")
                else:
                    # Assume path format: /bucket/key
                    path_parts = parsed_url.path.lstrip("/").split("/", 1)
                    if len(path_parts) == 2:
                        bucket, key = path_parts
                    else:
                        raise ValueError(
                            "Invalid URL format. Cannot extract bucket and key."
                        )
            else:
                raise ValueError("Invalid URL scheme. Must be s3://")
            return bucket, key

        try:
            bucket, key = parse_s3_url(url)
        except ValueError as e:
            return Response(
                {"detail": f"Error parsing URL: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Extract the evidence name from the key
        name = key.split("/")[-1]

        if source == "AWS":
            # Use boto3 to access AWS S3
            try:
                s3_client = boto3.client(
                    "s3",
                    aws_access_key_id=access_key_id,
                    aws_secret_access_key=access_key,
                    region_name=region,
                    endpoint_url=endpoint or None,
                )
                head_resp = s3_client.head_object(Bucket=bucket, Key=key)
                etag = head_resp["ETag"].strip('"')
            except botocore.exceptions.ClientError as e:
                error_code = e.response["Error"]["Code"]
                if error_code == "404":
                    return Response(
                        {"detail": "Object does not exist in S3."},
                        status=status.HTTP_404_NOT_FOUND,
                    )
                else:
                    return Response(
                        {"detail": f"AWS ClientError: {str(e)}"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            except Exception as e:
                return Response(
                    {"detail": f"Error accessing AWS S3: {str(e)}"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        elif source == "MINIO":
            try:
                is_secure = endpoint.startswith("https://")
                minio_client = Minio(
                    endpoint.replace("http://", "").replace("https://", ""),
                    access_key=access_key_id,
                    secret_key=access_key,
                    secure=is_secure,
                )
                stat = minio_client.stat_object(bucket, key)
                etag = stat.etag
            except Exception as e:
                return Response(
                    {"detail": f"Error accessing MinIO: {str(e)}"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        else:
            return Response(
                {"detail": "Invalid source specified. Must be AWS or MINIO."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Create the Evidence object
        evidence_data = {
            "name": name,
            "etag": etag,
            "os": os,
            "linked_case": linked_case,
            "source": source,
            "access_key_id": access_key_id,
            "access_key": access_key,
            "url": url,
            "region": region,
            "endpoint": endpoint,
        }

        serializer = EvidenceSerializer(data=evidence_data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        # Prepare the response data without sensitive fields
        response_data = serializer.data
        response_data.pop("access_key_id", None)
        response_data.pop("access_key", None)

        return Response(response_data, status=status.HTTP_201_CREATED)
