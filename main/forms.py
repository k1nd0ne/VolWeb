from django import forms
from main.models import Indicator
from django.forms import ModelForm, TextInput, Textarea, Select, FileInput

class IndicatorForm(forms.ModelForm):
    class Meta:
        model = Indicator
        fields = ('type', 'description', 'value', 'tlp')
        widgets = {
            'type': Select(attrs={'class': 'form-control', 'required': '""'}),
            'description': Textarea(
                attrs={'class': 'form-control', 'rows': "4", 'placeholder': 'Detailed information about this indicator',
                       'required': '""'}),
            'value': Textarea(
                attrs={'class': 'form-control', 'rows': "4", 'placeholder': 'The value of the Indicator',
                       'required': '""'}),
            'tlp': Select(attrs={'class': 'form-control', 'required': '""'}),
        }
