from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from .forms import *
from .models import Symbols
@login_required
def symbols(request):
    """Symbols main page

        Arguments:
        request : http request object

        Comment: Display all of the ISF file imported;
        """
    return render(request,'symbols/symbols.html',{'symbols':Symbols.objects.all(),'bind_form': BindSymbol(),'unbind_form':UnbindSymbol()})

@login_required
def add_symbols(request):
    """Symbols creation page

        Arguments:
        request : http request object

        Comment: Import an ISF;
        """
    if request.method == "POST":
        form = NewSymbolsForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return redirect('/symbols/')
    form = NewSymbolsForm()
    return render(request,'symbols/add_symbols.html',{'form':form})

@login_required
def custom_symbols(request):
    """Modify the description of an ISF file

        Arguments:
        request : http request object

        Comments:
        GET : Load the form page with intanced fields.
        POST : Apply the modifications
        """
    if request.method == 'GET':
        form = GetSymbols(request.GET)
        if form.is_valid():
            id = form.cleaned_data['symbols_id']
            symbols_record = Symbols.objects.get(pk=id)
            custom_form = CustomSymbolsForm(instance=symbols_record)
            return render(request,'symbols/custom_symbols.html',{'form': custom_form, 'symbols_id':id,'file':symbols_record.symbols_file})
    if request.method == 'POST':
        form = CustomSymbolsForm(request.POST, request.FILES)
        if form.is_valid():
            symbols_record = Symbols.objects.get(pk=form.cleaned_data['symbols_id'])
            symbols_record.name = form.cleaned_data['name']
            symbols_record.os = form.cleaned_data['os']
            symbols_record.description = form.cleaned_data['description']
            symbols_record.save()
            #Unbind from all investigation
            cases = UploadInvestigation.objects.filter(linked_isf = symbols_record)
            for case in cases:
                case.linked_isf = None
                case.save()
            return redirect('/symbols/')
        else:
            print(form.errors)

@login_required
def delete_symbols(request):
    """Delete a ISF file

        Arguments:
        request : http request object

        Comments:
        Delete the ISF File selected by the user.
        """
    if request.method == "POST":
        form = ManageSymbols(request.POST)
        if form.is_valid():
            isf = form.cleaned_data['symbols']
            isf.delete()
            return redirect('/symbols/')
        else:
            #Return a error django message (need to setup toast)
            return redirect('/symbols/')

@login_required
def bind_symbols(request):
    """Delete a ISF file

        Arguments:
        request : http request object

        Comments:
        Delete the ISF File selected by the user.
        """
    if request.method == "POST":
        form = BindSymbol(request.POST)
        if form.is_valid():
            isf  = form.cleaned_data['bind_symbols']
            case = form.cleaned_data['bind_investigation']
            case.linked_isf = isf
            case.save()
            return JsonResponse({'message': "success"})
        else:
            return JsonResponse({'message': "error"})

@login_required
def unbind_symbols(request):
    """Delete a ISF file

        Arguments:
        request : http request object

        Comments:
        Delete the ISF File selected by the user.
        """
    if request.method == "POST":
        form = UnbindSymbol(request.POST)
        if form.is_valid():
            isf  = form.cleaned_data['unbind_symbols']
            case = form.cleaned_data['unbind_investigation']
            case.linked_isf = None
            case.save()
            return JsonResponse({'message': "success"})
        else:
            return JsonResponse({'message': "error"})
