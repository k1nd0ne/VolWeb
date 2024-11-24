from rest_framework import viewsets
from .models import Symbol
from .serializers import SymbolSerializer
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile


class SymbolViewSet(viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated,)
    queryset = Symbol.objects.all()
    serializer_class = SymbolSerializer


class SymbolUploadView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        serializer = SymbolSerializer(data=request.data)
        if serializer.is_valid():
            symbol = serializer.save()

            # Serialize the symbol object before returning it in the response
            symbol_data = SymbolSerializer(symbol).data

            return Response(
                {"detail": "File uploaded successfully.", "symbol": symbol_data},
                status=status.HTTP_201_CREATED,
            )
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
