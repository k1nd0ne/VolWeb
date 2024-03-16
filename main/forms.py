from django import forms
from main.models import Indicator
from django.forms import ModelForm, TextInput, Textarea, Select, FileInput


class IndicatorForm(forms.ModelForm):
    class Meta:
        model = Indicator
        fields = ("type", "name", "description", "value")
        widgets = {
            "type": Select(attrs={"class": "form-control", "required": '""'}),
            "name": TextInput(
                attrs={
                    "class": "form-control",
                    "type": "text",
                    "required": "",
                }
            ),
            "description": Textarea(
                attrs={
                    "class": "form-control",
                    "rows": "4",
                    "placeholder": "Detailed information about this indicator",
                    "required": '""',
                }
            ),
            "value": Textarea(
                attrs={
                    "class": "form-control",
                    "rows": "4",
                    "placeholder": "The value of the Indicator",
                    "required": '""',
                }
            ),
        }
