from django import forms
from investigations.models import UploadInvestigation


class Tag(forms.Form):
    plugin_name = forms.CharField(max_length=255)
    artifact_id = forms.IntegerField()
    status = forms.CharField(max_length=12)


class ReportForm(forms.Form):
    case_id = forms.ModelChoiceField(queryset=UploadInvestigation.objects.all())
