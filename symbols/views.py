from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import permissions
from symbols.models import Symbol
from symbols.serializers import SymbolSerializer
from symbols.forms import SymbolForm

@login_required
def symbols(request):
    """Symbols main page

        Arguments:
        request : http request object

        Comment: Display all of the ISF file imported;
        """
    symbol_form = SymbolForm()
    return render(request, 'symbols/symbols.html',{'symbol_form':symbol_form})

class SymbolsApiView(APIView):
    # add permission to check if user is authenticated
    permission_classes = [permissions.IsAuthenticated]
    # 1. List all
    def get(self, request, *args, **kwargs):
        """
        Get all the symbols
        """
        symbols = Symbol.objects.all()
        serializer = SymbolSerializer(symbols, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        serializer = SymbolSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class SymbolApiView(APIView):
    # add permission to check if user is authenticated
    permission_classes = [permissions.IsAuthenticated]
    def get_object(self, id):
        """
        Helper method to get the object with given case_id
        """
        try:
            return Symbol.objects.get(id=id)
        except Symbol.DoesNotExist:
            return None

    def get(self, request, id, *args, **kwargs):
        """
        Retrieves the Case with given case_id
        """
        symbol = self.get_object(id)
        if not symbol:
            return Response(
                {"res": "Object with symbol id does not exists"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = SymbolSerializer(symbol)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request, id, *args, **kwargs):
        """
        Deletes the Symbol with the given id
        """
        symbol = self.get_object(id)
        if not symbol:
            return Response(
                {"res": "Object with symbol id does not exists"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        symbol.delete()
        return Response(
            {"res": "Object deleted"},
            status=status.HTTP_204_NO_CONTENT
        )
