from django import forms
from .models import UploadInvestigation, ProcessDump, FileDump
from django.forms import ModelForm, TextInput, Textarea, FileField, Select

class UploadFileForm(forms.ModelForm):
    class Meta:
        model = UploadInvestigation
        fields = ('name', 'title', 'description', 'status','os_version','investigators')
        widgets = {
                'title': TextInput(attrs={'class':'rounded query-input',}),
                'description': Textarea(attrs={'class':'rounded query-input','placeholder': 'Example : Client, machine usage,...'}),
                'os_version': Select(attrs={'value':'Windows','class': 'form-select query-input form-select-sm'}),
                'investigators': TextInput(attrs={'class':'d-none'}),
                'status': TextInput(attrs={'class':'d-none'}),
        }

class ManageInvestigation(forms.Form):
     sa_case_id = forms.CharField(max_length=255, widget=forms.TextInput(attrs={
        'class': 'd-none',}))

class DumpMemory(forms.ModelForm):
    class Meta:
        model = ProcessDump
        fields = ('pid','case_id',)
        widgets = {
                'pid': TextInput(attrs={'class': 'form-control rounded query-input','placeholder': 'PID'}),
                'case_id': TextInput(attrs={'class': 'd-none'}),
        }


class DumpFile(forms.ModelForm):
    class Meta:
        model = FileDump
        fields = ('offset','case_id',)
        widgets = {
                'offset': TextInput(attrs={'class': 'form-control rounded query-input','placeholder': 'File Offset (decimal)'}),
                'case_id': TextInput(attrs={'class': 'd-none'}),
        }

class DownloadDump(forms.Form):
     id = forms.CharField(max_length=100, widget=forms.TextInput(attrs={
        'class': 'd-none','value':'n/a'}))

class DownloadFile(forms.Form):
     id = forms.CharField(max_length=100, widget=forms.TextInput(attrs={
        'class': 'd-none','value':'n/a'}))
