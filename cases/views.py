from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import permissions
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from VolWeb.keyconfig import Secrets
from VolWeb.settings import DEBUG
from cases.serializers import CaseSerializer
from cases.forms import CaseForm
from cases.models import Case
from evidences.forms import EvidenceForm
from minio import Minio
import uuid, urllib3, ssl


@login_required
def case(request, case_id):
    case = Case.objects.get(case_id=case_id)
    evidence_form = EvidenceForm()
    return render(
        request, "cases/case.html", {"case": case, "evidence_form": evidence_form}
    )


class CasesApiView(APIView):
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    # 1. List all
    def get(self, request, *args, **kwargs):
        """
        List all the cases for given requested user
        """
        cases = Case.objects.all()
        serializer = CaseSerializer(cases, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    # 2. Create
    def post(self, request, *args, **kwargs):
        """
        Create Case with given case data and the associated bucket.
        If the bucket cannot be created -> no case creation.
        """
        bucket_uuid = uuid.uuid4()
        try:
            client = Minio(
                Secrets.AWS_ENDPOINT_HOST,
                Secrets.AWS_ACCESS_KEY_ID,
                Secrets.AWS_SECRET_ACCESS_KEY,
                secure=(not DEBUG),
            )
            client.make_bucket(str(bucket_uuid))
        except:
            return Response(
                "The bucket could not be created",
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        linked_users = request.data.getlist(
            "linked_users[]"
        )  # Get the raw list of linked_users
        if len(linked_users) < 1:
            return Response(
                {"error": "At least one linked user is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        linked_users_data = [{"username": user} for user in linked_users]
        data = {
            "case_bucket_id": bucket_uuid,
            "case_name": request.data.get("case_name"),
            "case_description": request.data.get("case_description"),
            "linked_users": linked_users_data,
        }
        serializer = CaseSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@login_required
def cases(request):
    """Load cases page

    Arguments:
    request : http request object

    Comments:
    Display the cases page
    """
    case_form = CaseForm()
    return render(request, "cases/cases.html", {"case_form": case_form})


class CaseApiView(APIView):
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get_object(self, case_id):
        """
        Helper method to get the object with given case_id
        """
        try:
            return Case.objects.get(case_id=case_id)
        except Case.DoesNotExist:
            return None

    # 3. Retrieve
    def get(self, request, case_id, *args, **kwargs):
        """
        Retrieves the Case with given case_id
        """
        case_instance = self.get_object(case_id)
        if not case_instance:
            return Response(
                {"res": "Object with case id does not exists"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = CaseSerializer(case_instance)
        return Response(serializer.data, status=status.HTTP_200_OK)

    # 4. Update
    def put(self, request, case_id, *args, **kwargs):
        """
        Updates the case item with given case_id if exists
        """
        case_instance = self.get_object(case_id)
        if not case_instance:
            return Response(
                {"res": "Object with case id does not exists"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        linked_users = request.data.getlist(
            "linked_users[]"
        )  # Get the raw list of linked_users
        linked_users_data = [{"username": user} for user in linked_users]
        data = {
            "case_name": request.data.get("case_name"),
            "case_description": request.data.get("case_description"),
            "linked_users": linked_users_data,
        }
        serializer = CaseSerializer(instance=case_instance, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # 5. Delete
    def delete(self, request, case_id, *args, **kwargs):
        """
        Deletes the case item with given case_id if exists
        """
        case_instance = self.get_object(case_id)
        if not case_instance:
            return Response(
                {"res": "Object with case id does not exists"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        case_instance.delete()
        return Response({"res": "Object deleted!"}, status=status.HTTP_200_OK)
