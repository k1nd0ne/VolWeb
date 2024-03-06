from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model
from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import permissions
from VolWeb.keyconfig import Secrets
from cases.models import Case
from evidences.models import Evidence
from symbols.models import Symbol
from django_celery_results.models import TaskResult
from windows_engine.serializers import TasksSerializer
from cases.serializers import CaseSerializer
from symbols.serializers import SymbolSerializer
from main.models import Indicator
from main.serializers import IndicatorSerializer
from main.forms import IndicatorForm


@login_required
def home(request):
    """Load home page

    Arguments:
    request : http request object

    Comments:
    Display the home page and pass the users/activities/analysis/
    """
    User = get_user_model()
    return render(request, "main/home.html", {"Users": User.objects.all()})

@login_required
def websocket_url(request):
    protocol = 'wss' if request.is_secure() else 'ws'
    ws_url = f"{protocol}://{Secrets.WEBSOCKET_HOST}"
    return JsonResponse({'websocket_url': ws_url})

@login_required
def minio_secrets(request):
    endpoint_info = {
        "url" : Secrets.AWS_ENDPOINT_URL,
        "key_id" : Secrets.AWS_ACCESS_KEY_ID,
        "key_password" : Secrets.AWS_SECRET_ACCESS_KEY
    }
    return JsonResponse({'endpoint': endpoint_info})



@login_required
def statistics(request):
    User = get_user_model()
    total_cases = Case.objects.count()
    total_evidences = Evidence.objects.count()
    total_evidences_progress = Evidence.objects.exclude(dump_status=100).count()
    total_evidences_windows = Evidence.objects.filter(dump_os="Windows").count()
    total_evidences_linux = Evidence.objects.filter(dump_os="Linux").count()
    total_symbols = Symbol.objects.count()
    total_users = User.objects.count()
    last_5_cases = Case.objects.all()[:5]
    last_5_isf = Symbol.objects.all()[:5]

    total_tasks = TaskResult.objects.filter(task_name="evidences.tasks.start_analysis");
    tasks_serializer = TasksSerializer(total_tasks, many=True)
    cases_serializer = CaseSerializer(last_5_cases, many=True)
    symbols_serializer = SymbolSerializer(last_5_isf, many=True)

    return JsonResponse({
    'total_cases': total_cases,
    'total_evidences': total_evidences,
    'total_evidences_progress': total_evidences_progress,
    'total_evidences_windows': total_evidences_windows,
    'total_evidences_linux': total_evidences_linux,
    'total_symbols': total_symbols,
    'total_users': total_users,
    'tasks': tasks_serializer.data,
    'last_5_cases': cases_serializer.data,
    'last_5_isf': symbols_serializer.data,
    })

class IndicatorApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request, *args, **kwargs):
        """
        Get all the symbols
        """
        indicators = Indicator.objects.all()
        serializer = IndicatorSerializer(indicators, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        serializer = IndicatorSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class IndicatorCaseApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request, case_id, *args, **kwargs):
        """
        Get all the symbols
        """
        indicators = Indicator.objects.filter(evidence__dump_linked_case=case_id)
        serializer = IndicatorSerializer(indicators, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
