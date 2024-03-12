from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from evidences.forms import EvidenceForm
from rest_framework.views import APIView
from rest_framework import permissions
from rest_framework import status
from evidences.models import Evidence
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.response import Response
from evidences.serializers import EvidenceSerializer
from minio import Minio
from VolWeb.keyconfig import Secrets


@login_required
def evidences(request):
    """Load evidence page

    Arguments:
    request : http request object

    Comments:
    Display the evidences page
    """
    evidence_form = EvidenceForm()
    return render(request, "evidences/evidences.html", {"evidence_form": evidence_form})


class CaseEvidenceApiView(APIView):
    # add permission to check if user is authenticated
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get(self, request, case_id, *args, **kwargs):
        """
        List all the evidences for given requested user
        """
        evidences = Evidence.objects.filter(dump_linked_case=case_id)
        serializer = EvidenceSerializer(evidences, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class EvidenceAPIView(APIView):
    # add permission to check if user is authenticated
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    # 1. List all
    def get(self, request, *args, **kwargs):
        """
        List all the evidence for given requested user
        """
        evidences = Evidence.objects.all()
        serializer = EvidenceSerializer(evidences, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    # 2. Create
    def post(self, request, *args, **kwargs):
        """
        Create an evidence
        """
        dump_etag = request.data.get("dump_etag")
        if Evidence.objects.filter(dump_etag=dump_etag).exists():
            return Response(
                {"error": "Evidence with this ETag already exists."},
                status=status.HTTP_409_CONFLICT,
            )

        data = {
            "dump_name": request.data.get("dump_name"),
            "dump_etag": dump_etag,
            "dump_os": request.data.get("dump_os"),
            "dump_linked_case": request.data.get("dump_linked_case"),
        }
        serializer = EvidenceSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EvidenceDetailApiView(APIView):
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get_object(self, dump_id):
        """
        Helper method to get the object with given dump_id
        """
        try:
            return Evidence.objects.get(dump_id=dump_id)
        except Evidence.DoesNotExist:
            return None

    # 1. Retrieve
    def get(self, request, dump_id, *args, **kwargs):
        """
        Retrieves the Evidence with given dump_id
        """
        evidence_instance = self.get_object(dump_id)
        if not evidence_instance:
            return Response(
                {"res": "Object with case id does not exists"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = EvidenceSerializer(evidence_instance)
        return Response(serializer.data, status=status.HTTP_200_OK)

    # 2. Delete
    def delete(self, request, dump_id, *args, **kwargs):
        """
        Deletes the evidence item with given dump_id if exists
        """
        evidence_instance = self.get_object(dump_id)
        if not evidence_instance:
            return Response(
                {"res": "Object with evidence id does not exists"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Now, we get the bucket associated to this evidence.
        bucket = evidence_instance.dump_linked_case.case_bucket_id
        object = evidence_instance.dump_name
        try:
            # TODO: Env variables!
            client = Minio(
                Secrets.AWS_ENDPOINT_HOST,
                Secrets.AWS_ACCESS_KEY_ID,
                Secrets.AWS_SECRET_ACCESS_KEY,
                secure=False,
            )
            client.remove_object(str(bucket), object)
        except:
            return Response(
                "The evidence could not be removed",
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        evidence_instance.delete()

        return Response({"res": "Object deleted!"}, status=status.HTTP_200_OK)
