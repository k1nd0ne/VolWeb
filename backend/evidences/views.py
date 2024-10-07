from rest_framework import viewsets
from .models import Evidence
from .serializers import EvidenceSerializer
from rest_framework.permissions import IsAuthenticated

class EvidenceViewSet(viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated,)
    queryset = Evidence.objects.all()
    serializer_class = EvidenceSerializer
