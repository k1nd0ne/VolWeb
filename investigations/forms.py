from django import forms
from investigations.models import UploadInvestigation
from windows_engine.models import ProcessDump, FileDump
from django.forms import ModelForm, TextInput, Textarea, FileField, Select


class UploadFileForm(forms.ModelForm):
    class Meta:
        model = UploadInvestigation
        fields = ('name', 'title', 'description', 'status', 'os_version', 'investigators')
        widgets = {
            'title': TextInput(
                attrs={'class': 'form-control', 'type': 'text', 'placeholder': 'Hostname', 'required': ''}),
            'description': Textarea(attrs={"class": "form-control", "rows": "4", "required": "",
                                           'placeholder': 'Example : Client, machine usage,...'}),
            'os_version': Select(attrs={'value': 'Windows', 'class': 'form-select'}),
            'investigators': TextInput(attrs={'class': 'd-none'}),
            'status': TextInput(attrs={'class': 'd-none'}),
        }



class CustomInvestigation(forms.ModelForm):
    class Meta:
        model = UploadInvestigation
        fields = ('title', 'description', 'os_version')
        widgets = {
            'title': TextInput(
                attrs={'class': 'form-control', 'type': 'text', 'placeholder': 'Hostname', 'required': ''}),
            'description': Textarea(attrs={"class": "form-control", "rows": "4", "required": "",
                                           'placeholder': 'Example : Client, machine usage,...'}),
            'os_version': Select(attrs={'value': 'Windows', 'class': 'form-select'}),
        }



class ManageInvestigation(forms.Form):
    sa_case_id = forms.ModelChoiceField(queryset=UploadInvestigation.objects.all())


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
