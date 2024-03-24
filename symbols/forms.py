from django import forms
from symbols.models import Symbol
from django.forms import ModelForm, TextInput, Textarea, Select, FileInput


class SymbolForm(forms.ModelForm):
    class Meta:
        model = Symbol
        fields = ("name", "os", "description", "symbols_file")
        widgets = {
            "name": TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Usually the distribution name and kernel version",
                    "required": '""',
                }
            ),
            "os": Select(attrs={"class": "form-control", "required": '""'}),
            "description": Textarea(
                attrs={
                    "class": "form-control",
                    "rows": "4",
                    "placeholder": "Detailed information about this ISF",
                    "required": '""',
                }
            ),
            "symbols_file": FileInput(attrs={"class": "form-control"}),
        }
