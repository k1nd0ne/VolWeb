from rest_framework import viewsets
from rest_framework.views import APIView
from .models import Evidence
from .serializers import EvidenceSerializer
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from evidences.models import Evidence
from volatility_engine.models import VolatilityPlugin
from collections import Counter




class EvidenceViewSet(viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated,)
    queryset = Evidence.objects.all()
    serializer_class = EvidenceSerializer
class EvidenceStatisticsApiView(APIView):
    """
    API view to get statistics about an evidence.
    """
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        evidence_id = kwargs.get('id')
        if not evidence_id:
            return Response({
                "error": "Evidence ID is required"
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            evidence = Evidence.objects.get(id=evidence_id)
        except Evidence.DoesNotExist:
            return Response({
                "error": "Evidence with specified ID does not exist"
            }, status=status.HTTP_404_NOT_FOUND)

        plugins = VolatilityPlugin.objects.filter(evidence=evidence).exclude(category="Other")

        # Calculate the number of artefacts per plugin category
        category_artefacts_counter = Counter()
        for plugin in plugins:
            if plugin.results:
                artefacts_count = len(plugin.artefacts)
                category_artefacts_counter[plugin.category] += artefacts_count

        total_ran = plugins.count()
        total_results = plugins.filter(results=True).count()

        return Response({
            "categories": dict(category_artefacts_counter),
            "total_ran": total_ran,
            "total_results": total_results
        }, status=status.HTTP_200_OK)
