from django import forms
from .models import UploadInvestigation
from django.forms import ModelForm, CheckboxSelectMultiple, TextInput, Textarea, MultipleChoiceField, FileField

class UploadFileForm(forms.ModelForm):
    class Meta:
        model = UploadInvestigation
        fields = ('name', 'title', 'description', 'status','os_version','investigators')
        widgets = {
                'title': TextInput(attrs={'class':'rounded query-input',}),
                'description': Textarea(attrs={'class':'rounded query-input','placeholder': 'Example : Client, machine usage,...'}),
                'os_version': TextInput(attrs={'class':'text-white rounded query-input','placeholder':'Example : Windows Server 2008 R2'}),
                'investigators': TextInput(attrs={'class':'d-none'}),
                'status': TextInput(attrs={'class':'d-none'}),
        }

class ManageInvestigation(forms.Form):
     id = forms.CharField(max_length=100, widget=forms.TextInput(attrs={
        'class': 'd-none',}))
     action = forms.CharField(max_length=100, widget=forms.TextInput(attrs={
        'class': 'd-none',}))

class DumpMemory(forms.Form):
     id = forms.CharField(max_length=100, widget=forms.TextInput(attrs={
         'class': 'd-none','id':'id_id','value':'n/a'}))
     pid = forms.IntegerField(widget=forms.TextInput(attrs={
        'class': 'form-control','placeholder': 'PID'}))
