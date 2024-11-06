from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from stix2.exceptions import InvalidValueError
from rest_framework import generics
from core.serializers import UserSerializer
from core.models import Indicator
from core.serializers import IndicatorSerializer
from django.http import JsonResponse, HttpResponse
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
        except Exception as e:
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
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get(self, request, dump_id, *args, **kwargs):
        """
        Get all the indicators for an evidence
        """
        indicators = Indicator.objects.filter(evidence__dump_id=dump_id)
        serializer = IndicatorSerializer(indicators, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class IndicatorCaseApiView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get(self, request, case_id, *args, **kwargs):
        """
        Get all the indicators for a case
        """
        indicators = Indicator.objects.filter(evidence__dump_linked_case=case_id)
        serializer = IndicatorSerializer(indicators, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class IndicatorExportApiView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get(self, request, case_id, *args, **kwargs):
        """
        Get all the indicators for a case and return as a file blob
        """
        indicators = Indicator.objects.filter(evidence__dump_linked_case=case_id)
        bundle = export_bundle(indicators)
        response = HttpResponse(bundle, content_type="application/octet-stream")
        response[
            "Content-Disposition"
        ] = 'attachment; filename="indicators_case_{}.json"'.format(case_id)
        return response
