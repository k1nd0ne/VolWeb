from rest_framework import viewsets, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from django.conf import settings
from django.core.files.storage import default_storage
from .models import Case, UploadSession
from evidences.models import Evidence
from .serializers import CaseSerializer, InitiateUploadSerializer, UploadChunkSerializer, CompleteUploadSerializer
import os
import shutil


class CaseViewSet(viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated,)
    queryset = Case.objects.all()
    serializer_class = CaseSerializer

    def create(self, request, *args, **kwargs):
        # Extract direct fields
        name = request.data.get("name")
        description = request.data.get("description")
        linked_users_ids = request.data.get("linked_users", [])

        # Create the case instance with direct fields
        case = Case(name=name, description=description)
        case.save()

        # Add linked users
        for user_id in linked_users_ids:
            case.linked_users.add(user_id)

        case.save()

        serializer = CaseSerializer(case)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class CompleteUploadView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = CompleteUploadSerializer(data=request.data)
        if serializer.is_valid():
            upload_id = serializer.validated_data['upload_id']

            try:
                upload_session = UploadSession.objects.get(upload_id=upload_id, user=request.user)
            except UploadSession.DoesNotExist:
                return Response({'error': 'Invalid upload_id or unauthorized access.'}, status=status.HTTP_400_BAD_REQUEST)

            temp_dir = os.path.join(settings.MEDIA_ROOT, 'temp_uploads', str(upload_id))

            if not os.path.exists(temp_dir):
                return Response({'error': 'Upload session has expired or is invalid.'}, status=status.HTTP_400_BAD_REQUEST)

            # Get the list of chunk files and sort them by part_number
            chunk_files = os.listdir(temp_dir)
            try:
                chunk_files.sort(key=lambda x: int(x.split('_')[1]))
            except ValueError:
                return Response({'error': 'Invalid chunk filenames.'}, status=status.HTTP_400_BAD_REQUEST)

            final_filename = upload_session.filename
            final_file_path = os.path.join(settings.MEDIA_ROOT, 'evidences', final_filename)
            os.makedirs(os.path.dirname(final_file_path), exist_ok=True)

            # Assemble the chunks into the final file
            with open(final_file_path, 'wb') as final_file:
                for chunk_file in chunk_files:
                    chunk_path = os.path.join(temp_dir, chunk_file)
                    with open(chunk_path, 'rb') as chunk:
                        shutil.copyfileobj(chunk, final_file)

            # Clean up temporary files and directory
            shutil.rmtree(temp_dir)
            # Create the Evidence record
            evidence = Evidence.objects.create(
                name=final_filename,
                url=f"file://{os.path.join(settings.MEDIA_ROOT, 'evidences', final_filename)}",
                linked_case=upload_session.case,
                os=upload_session.os,
                etag=upload_session.upload_id
            )

            # Delete the upload session
            upload_session.delete()

            return Response({'status': 'upload complete', 'evidence_id': evidence.id}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class UploadChunkView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = UploadChunkSerializer(data=request.data)
        if serializer.is_valid():
            upload_id = serializer.validated_data['upload_id']
            part_number = serializer.validated_data['part_number']
            chunk = serializer.validated_data['chunk']

            try:
                UploadSession.objects.get(upload_id=upload_id, user=request.user)
            except UploadSession.DoesNotExist:
                return Response({'error': 'Invalid upload_id or unauthorized access.'}, status=status.HTTP_400_BAD_REQUEST)

            temp_dir = os.path.join(settings.MEDIA_ROOT, 'temp_uploads', str(upload_id))
            if not os.path.exists(temp_dir):
                return Response({'error': 'Upload session has expired or is invalid.'}, status=status.HTTP_400_BAD_REQUEST)

            chunk_filename = f'part_{part_number}'
            chunk_path = os.path.join(temp_dir, chunk_filename)

            # Save the chunk
            with default_storage.open(chunk_path, 'wb+') as destination:
                for chunk_part in chunk.chunks():
                    destination.write(chunk_part)

            return Response({'status': 'chunk received'}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class InitiateUploadView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = InitiateUploadSerializer(data=request.data)
        if serializer.is_valid():
            filename = serializer.validated_data['filename']
            case_id = serializer.validated_data['case_id']
            operating_system = serializer.validated_data['os']

            try:
                case = Case.objects.get(id=case_id)
            except Case.DoesNotExist:
                return Response({'error': 'Invalid case_id.'}, status=status.HTTP_400_BAD_REQUEST)

            # Create a new upload session
            upload_session = UploadSession.objects.create(
                filename=filename,
                case=case,
                user=request.user,
                os=operating_system,
            )

            # Create a temporary directory for the upload session
            upload_id = str(upload_session.upload_id)
            temp_dir = os.path.join(settings.MEDIA_ROOT, 'temp_uploads', upload_id)
            os.makedirs(temp_dir, exist_ok=True)

            return Response({'upload_id': upload_id}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
