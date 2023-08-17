from cases.models import Case
from django import forms
from django.forms import TextInput, Textarea, SelectMultiple



class CaseForm(forms.ModelForm):
    class Meta:
        model = Case
        fields = ['case_name', 'case_description', 'linked_users']
        widgets = {
            'case_name': TextInput(attrs={'class': 'form-control form-control-sm', 'type': 'text', 'required': ''}),
            'case_description': Textarea(attrs={"class": "form-control form-control-sm", "rows": "4", "required": ""}),
            'linked_users': SelectMultiple(attrs={'class': 'form-control form-control-sm'})
        }
