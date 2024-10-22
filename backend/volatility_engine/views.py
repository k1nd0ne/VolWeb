from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import VolatilityPlugin
from evidences.models import Evidence
from .serializers import (
    VolatilityPluginDetailSerializer,
    VolatilityPluginNameSerializer,
)


class EvidencePluginsView(APIView):
    def get(self, request, evidence_id):
        try:
            evidence = Evidence.objects.get(id=evidence_id)
            plugins = VolatilityPlugin.objects.filter(evidence=evidence)
            serializer = VolatilityPluginNameSerializer(plugins, many=True)

            return Response(serializer.data, status=status.HTTP_200_OK)

        except Evidence.DoesNotExist:
            return Response(
                {"error": "Evidence not found"}, status=status.HTTP_404_NOT_FOUND
            )


class PluginArtefactsView(APIView):
    def get(self, request, evidence_id, plugin_name):
        try:
            evidence = Evidence.objects.get(id=evidence_id)
            plugin = VolatilityPlugin.objects.get(evidence=evidence, name=plugin_name)
            serializer = VolatilityPluginDetailSerializer(plugin)

            return Response(serializer.data, status=status.HTTP_200_OK)

        except Evidence.DoesNotExist:
            return Response(
                {"error": "Evidence not found"}, status=status.HTTP_404_NOT_FOUND
            )
        except VolatilityPlugin.DoesNotExist:
            return Response(
                {"error": "Plugin not found"}, status=status.HTTP_404_NOT_FOUND
            )
