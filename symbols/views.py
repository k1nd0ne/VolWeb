from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .forms import NewSymbolsForm

@login_required
def symbols(request):
    """Symbols table main page

        Arguments:
        request : http request object

        Comment: Display all of the ISF imported;
        """
    return render(request,'symbols/symbols.html',)

@login_required
def addsymbols(request):
    """Symbols creation page

        Arguments:
        request : http request object

        Comment: Import an ISF;
        """
    form = NewSymbolsForm()
    return render(request,'symbols/addsymbols.html',{'form':form})
