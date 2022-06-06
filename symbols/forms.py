from django import forms
from .models import Symbols
from django.forms import ModelForm, TextInput, Textarea, ModelChoiceField, Select, FileInput

#This ModelForm is made to create a new IOC
class NewSymbolsForm(forms.ModelForm):
    class Meta:
        model = Symbols
        fields = ('name','os','description', 'symbols_file')
        widgets = {
             'name': TextInput(attrs={'class':'form-control','placeholder': 'Usually the distribution name and kernel version','required':'""'}),
             'os': Select(attrs={'class': 'form-control','required':'""'}),
             'description' : Textarea(attrs={'class':'form-control','rows':"4",'placeholder':'Detailed informations about this ISF','required':'""'}),
             'symbols_file' : FileInput(attrs={'class': 'form-control','required':'""'}),
         }
