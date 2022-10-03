from django import forms
from .models import Symbols
from investigations.models import UploadInvestigation
from django.forms import ModelForm, TextInput, Textarea, Select, FileInput


# This ModelForm is made to create a new IOC
class SymbolsForm(forms.ModelForm):
    class Meta:
        model = Symbols
        fields = ('name', 'os', 'description', 'symbols_file')
        widgets = {
            'name': TextInput(
                attrs={'class': 'form-control', 'placeholder': 'Usually the distribution name and kernel version',
                       'required': '""'}),
            'os': Select(attrs={'class': 'form-control', 'required': '""'}),
            'description': Textarea(
                attrs={'class': 'form-control', 'rows': "4", 'placeholder': 'Detailed information about this ISF',
                       'required': '""'}),
            'symbols_file': FileInput(attrs={'class': 'form-control'}),
        }


class GetSymbols(forms.Form):
    symbols_id = forms.CharField(max_length=100, widget=forms.TextInput(attrs={
        'class': 'd-none', }))


class ManageSymbols(forms.Form):
    symbols = forms.ModelChoiceField(queryset=Symbols.objects.all(), required=True,
                                     widget=forms.TextInput(attrs={'type': 'hidden'}))


class BindSymbol(forms.Form):
    bind_symbols = forms.ModelChoiceField(queryset=Symbols.objects.all(), required=True,
                                          widget=forms.TextInput(attrs={'type': 'hidden'}))
    bind_investigation = forms.ModelChoiceField(queryset=UploadInvestigation.objects.all(), required=True,
                                                widget=forms.Select(attrs={'class': 'form-control'}))


class UnbindSymbol(forms.Form):
    unbind_symbols = forms.ModelChoiceField(queryset=Symbols.objects.all(), required=True,
                                            widget=forms.TextInput(attrs={'type': 'hidden'}))
    unbind_investigation = forms.ModelChoiceField(queryset=UploadInvestigation.objects.all(), required=True,
                                                  widget=forms.Select(attrs={'class': 'form-control'}))
