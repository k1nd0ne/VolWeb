from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import permissions
from cases.serializers import CaseSerializer
from cases.forms import CaseForm
from cases.models import Case
from minio import Minio
import uuid


class CaseApiView(APIView):
    # add permission to check if user is authenticated
    permission_classes = [permissions.IsAuthenticated]

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
            client = Minio("localhost:9000", "user", "password", secure=False)
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
            return Response({'error':'message'}, status=status.HTTP_400_BAD_REQUEST)
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


class CaseDetailApiView(APIView):
    # add permission to check if user is authenticated
    permission_classes = [permissions.IsAuthenticated]

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
