from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from stix2.exceptions import InvalidValueError
from rest_framework import generics
from core.serializers import UserSerializer, TypeSerializer
from core.models import TYPES, Indicator
from cases.models import Case
from cases.serializers import CaseSerializer
from evidences.models import Evidence
from symbols.models import Symbol
from symbols.serializers import SymbolSerializer
from core.serializers import IndicatorSerializer, TasksSerializer
from django_celery_results.models import TaskResult
from django.http import HttpResponse
from rest_framework import status
from core.stix import export_bundle, create_indicator


class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=204)
        except Exception:
            return Response(status=400)


class UserList(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer


class IndicatorApiView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        indicators = Indicator.objects.all()
        serializer = IndicatorSerializer(indicators, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        serializer = IndicatorSerializer(data=request.data)
        if serializer.is_valid():
            # First check indicator creation using stix2 lib to identify any wrong input value.
            instance = Indicator(**serializer.validated_data)
            try:
                create_indicator(instance)
            except InvalidValueError as e:
                return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, indicator_id, *args, **kwargs):
        try:
            indicator = Indicator.objects.get(id=indicator_id)
            indicator.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Indicator.DoesNotExist:
            return Response(
                {"message": "Indicator not found."}, status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class IndicatorEvidenceApiView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, evidence_id, *args, **kwargs):
        """
        Get all the indicators for an evidence
        """
        indicators = Indicator.objects.filter(evidence__id=evidence_id)
        serializer = IndicatorSerializer(indicators, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class IndicatorCaseApiView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, case_id, *args, **kwargs):
        """
        Get all the indicators for a case
        """
        indicators = Indicator.objects.filter(evidence__linked_case=case_id)
        serializer = IndicatorSerializer(indicators, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class IndicatorExportApiView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, case_id, *args, **kwargs):
        """
        Get all the indicators for a case and return as a file blob
        """
        indicators = Indicator.objects.filter(evidence__linked_case=case_id)
        bundle = export_bundle(indicators)
        response = HttpResponse(bundle, content_type="application/octet-stream")
        response["Content-Disposition"] = (
            'attachment; filename="indicators_case_{}.json"'.format(case_id)
        )
        return response


class IndicatorTypeListAPIView(APIView):
    """
    API view to list all indicator types.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        types = [{"value": type_[0], "display": type_[1]} for type_ in TYPES]
        serializer = TypeSerializer(data=types, many=True)
        if serializer.is_valid():
            return Response(serializer.validated_data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class StatisticsApiView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        total_cases = Case.objects.count()
        total_evidences = Evidence.objects.count()
        total_evidences_progress = Evidence.objects.exclude(status=100).count()
        total_evidences_windows = Evidence.objects.filter(os="windows").count()
        total_evidences_linux = Evidence.objects.filter(os="linux").count()
        total_symbols = Symbol.objects.count()
        total_users = User.objects.count()
        last_5_cases = Case.objects.all()[:5]
        last_5_isf = Symbol.objects.all()[:5]

        total_tasks = TaskResult.objects.filter(task_name="Windows.Engine")
        tasks_serializer = TasksSerializer(total_tasks, many=True)
        cases_serializer = CaseSerializer(last_5_cases, many=True)
        symbols_serializer = SymbolSerializer(last_5_isf, many=True)

        return Response(
            {
                "total_cases": total_cases,
                "total_evidences": total_evidences,
                "total_evidences_progress": total_evidences_progress,
                "total_evidences_windows": total_evidences_windows,
                "total_evidences_linux": total_evidences_linux,
                "total_symbols": total_symbols,
                "total_users": total_users,
                "tasks": tasks_serializer.data,
                "last_5_cases": cases_serializer.data,
                "last_5_isf": symbols_serializer.data,
            },
            status=status.HTTP_200_OK,
        )
