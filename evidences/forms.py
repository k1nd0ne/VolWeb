from evidences.models import Evidence
from cases.models import Case
from django import forms
from django.forms import TextInput, Select, PasswordInput


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

class BindEvidenceForm(forms.ModelForm):
    class Meta:
        model = Evidence
        fields = ["dump_name", "dump_os", "dump_linked_case", "dump_access_key_id", "dump_access_key", "dump_url", "dump_source", "dump_endpoint", "dump_region"]
        dump_linked_case = forms.ModelChoiceField(
            queryset=Case.objects.all(), required=True
        )
        widgets = {
            "dump_name": TextInput(
                attrs={
                    "class": "form-control form-control-sm",
                    "type": "text",
                    "required": "",
                    "id": "id_bind_dump_name",
                }
            ),
            "dump_os": Select(
                attrs={
                    "value": "Windows",
                    "class": "form-select form-control form-control-sm",
                    "id": "id_bind_dump_os",
                }
            ),
            "dump_linked_case": Select(
                attrs={"class": "form-select form-control form-control-sm",
                    "id": "id_bind_dump_linked_case"}
            ),
            "dump_access_key_id": TextInput(
                attrs={
                    "class": "form-control form-control-sm",
                    "type": "text",
                    "required": "",
                    "id": "id_bind_dump_access_key_id",
                }
            ),
            "dump_access_key": PasswordInput(
                attrs={
                    "class": "form-control form-control-sm",
                    "type": "password",
                    "required": "",
                    "id": "id_bind_dump_access_key",
                    "aria-describedby":"access_key_help",
                }
            ),
            "dump_url": TextInput(
                attrs={
                    "class": "form-control form-control-sm",
                    "type": "text",
                    "required": "",
                    "placeholder": "s3://",
                    "id": "id_bind_dump_url",

                }
            ),
            "dump_source": Select(
                attrs={
                    "class": "form-select form-control form-control-sm",
                    "id": "id_bind_dump_source",
                }
            ),
            "dump_region": TextInput(
                attrs={
                    "class": "form-control form-control-sm",
                    "type": "text",
                    "required": "",
                    "id": "id_bind_dump_region",

                }
            ),
            "dump_endpoint": TextInput(
                attrs={
                    "class": "form-control form-control-sm",
                    "type": "text",
                    "required": "",
                    "id": "id_bind_dump_endpoint",
                }
            ),

        }
