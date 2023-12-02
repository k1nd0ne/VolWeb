from evidences.models import Evidence
from cases.models import Case
from django import forms
from django.forms import TextInput, Select


class EvidenceForm(forms.ModelForm):
    class Meta:
        model = Evidence
        fields = ["dump_name", "dump_os", "dump_linked_case"]
        dump_linked_case = forms.ModelChoiceField(
            queryset=Case.objects.all(), required=True
        )
        widgets = {
            "dump_name": TextInput(
                attrs={
                    "class": "form-control form-control-sm",
                    "type": "text",
                    "required": "",
                }
            ),
            "dump_os": Select(
                attrs={
                    "value": "Windows",
                    "class": "form-select form-control form-control-sm",
                }
            ),
            "dump_linked_case": Select(
                attrs={"class": "form-select form-control form-control-sm "}
            ),
        }
