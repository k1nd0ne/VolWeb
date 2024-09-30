from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from .models import Case
from .serializers import CaseSerializer

class CaseViewSet(viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated, )
    queryset = Case.objects.all()
    serializer_class = CaseSerializer
