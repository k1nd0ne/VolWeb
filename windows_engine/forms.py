from django import forms
from windows_engine.models import ProcessDump, FileDump
from django.forms import ModelForm, TextInput, Textarea, FileField, Select
from investigations.models import UploadInvestigation


class DumpMemory(forms.ModelForm):
    class Meta:
        model = ProcessDump
        fields = ('pid', 'case_id',)
        widgets = {
            'pid': TextInput(attrs={'class': 'form-control rounded query-input', 'placeholder': 'PID'}),
            'case_id': TextInput(attrs={'class': 'd-none'}),
        }


class DumpFile(forms.ModelForm):
    class Meta:
        model = FileDump
        fields = ('offset', 'case_id',)
        widgets = {
            'offset': TextInput(
                attrs={'class': 'form-control rounded query-input', 'placeholder': 'File Offset (decimal)'}),
            'case_id': TextInput(attrs={'class': 'd-none'}),
        }


class DownloadDump(forms.Form):
    id = forms.CharField(max_length=255, widget=forms.TextInput(attrs={
        'class': 'd-none', 'value': 'n/a'}))


class DownloadFile(forms.Form):
    id = forms.CharField(max_length=255, widget=forms.TextInput(attrs={
        'class': 'd-none', 'value': 'n/a'}))


class DownloadHive(forms.Form):
    filename = forms.CharField(max_length=255, widget=forms.TextInput(attrs={
        'class': 'd-none', 'value': 'n/a'}))


class Tag(forms.Form):
    plugin_name = forms.CharField(max_length=255)
    artifact_id = forms.IntegerField()
    status = forms.CharField(max_length=12)


class ReportForm(forms.Form):
    case_id = forms.ModelChoiceField(queryset=UploadInvestigation.objects.all())
