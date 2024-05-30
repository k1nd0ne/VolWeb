from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from evidences.forms import EvidenceForm, BindEvidenceForm
from rest_framework.views import APIView
from rest_framework import permissions
from rest_framework import status
from evidences.models import Evidence
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.response import Response
from evidences.serializers import AnalysisStartSerializer, EvidenceSerializer
from minio import Minio
from evidences.tasks import start_analysis
from VolWeb.keyconfig import Secrets
from VolWeb.settings import DEBUG


@login_required
def evidences(request):
    """
    This view will return the evidence template with a form to add a new evidence.
    :param request: http request
    :return: render the evidences.html page with a form.
    """
    evidence_form = EvidenceForm()
    bind_evidence_form = BindEvidenceForm()
    return render(request, "evidences/evidences.html", {"evidence_form": evidence_form, "bind_evidence_form":bind_evidence_form})

class CaseEvidenceApiView(APIView):
    """
    Case/Evidence API View
    This API view allows an authenticated user to get the evidences associated to a given case
    """

    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get(self, request, case_id, *args, **kwargs):
        """
        get request handler
        :return: serialized evidences linked to the case.
        """
        evidences = Evidence.objects.filter(dump_linked_case=case_id)
        serializer = EvidenceSerializer(evidences, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class EvidenceAPIView(APIView):
    """
    Evidence API View
    This API view allows an authenticated user to get all of the evidences and create one.
    """
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get(self, request, *args, **kwargs):
        """
        get request handler
        :return: serialized evidences.
        """
        evidences = Evidence.objects.all()
        serializer = EvidenceSerializer(evidences, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        """
        post request handler
        :return: the new serialized evidence created
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



class BindEvidence(APIView):
    """
    Bind Evidence API View
    This API view allows an authenticated user to bind an existing evidence.
    """
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def post(self, request, *args, **kwargs):
        """
        post request handler
        :return: the new serialized evidence created
        """
        dump_etag = request.data.get("dump_etag")
        if Evidence.objects.filter(dump_etag=dump_etag).exists():
            return Response(
                {"error": "Evidence with this ETag already exists."},
                status=status.HTTP_409_CONFLICT,
            )
        print(request.data)
        source = request.data.get('dump_source')
        # if source == "AWS":
        #     # Try to fetch the evidence etag
        # elif source == "MINIO":
        #     # Try to fetch the evidence etag
        # else:
        #     return Response(status=status.HTTP_404_NOT_FOUND)
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
        print(serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class EvidenceDetailApiView(APIView):
    """
    EvidenceDetail API View
    This API view allows an authenticated user to get all of the details for a given evidence/dump id.
    """

    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get_object(self, dump_id):
        """
        Helper method to get the object with given dump_id
        """
        try:
            return Evidence.objects.get(dump_id=dump_id)
        except Evidence.DoesNotExist:
            return None

    def get(self, request, dump_id, *args, **kwargs):
        """
        get request handler
        :return: serialized evidence requested if found.
        """
        evidence_instance = self.get_object(dump_id)
        if not evidence_instance:
            return Response(
                {"res": "Object with case id does not exists"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = EvidenceSerializer(evidence_instance)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request, dump_id, *args, **kwargs):
        """
        delete request handler
        :return: result message with the status of the action.
        """
        evidence_instance = self.get_object(dump_id)
        if not evidence_instance:
            return Response(
                {"res": "Object with evidence id does not exists"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        bucket = evidence_instance.dump_linked_case.case_bucket_id
        object = evidence_instance.dump_name
        try:
            client = Minio(
                Secrets.AWS_ENDPOINT_HOST,
                Secrets.AWS_ACCESS_KEY_ID,
                Secrets.AWS_SECRET_ACCESS_KEY,
                secure=(not DEBUG),
            )
            client.remove_object(str(bucket), object)
        except:
            return Response(
                "The evidence could not be removed from the remote bucket",
                status=status.HTTP_404_NOT_FOUND,
            )
        evidence_instance.delete()

        return Response({"res": "Evidence deleted."}, status=status.HTTP_200_OK)


class LaunchTaskAPIView(APIView):
    """
    Launch Task API View
    This API view allows an authenticated user to restart the analysis of a memory image.
    """

    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [SessionAuthentication]

    def get_object(self, dump_id):
        """
        Helper method to get the evidence with given dump_id
        """
        try:
            return Evidence.objects.get(dump_id=dump_id)
        except Evidence.DoesNotExist:
            return None

    def post(self, request, *args, **kwargs):
        """
        post request handler
        :return: result message with the status of the action and HTTP code.
        """
        serializer = AnalysisStartSerializer(data=request.data)
        if serializer.is_valid():
            dump_id = serializer.validated_data.get("dump_id")
            evidence_instance = self.get_object(dump_id)
            if evidence_instance:
                evidence_instance.dump_status = 0
                evidence_instance.save()
                start_analysis.delay(evidence_instance.dump_id)
                return Response(
                    {"status": "Analysis launched"}, status=status.HTTP_202_ACCEPTED
                )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
