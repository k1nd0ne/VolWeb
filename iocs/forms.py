from django import forms
from .models import IOC
from investigations.models import UploadInvestigation
from django.forms import ModelForm, TextInput, Textarea, ModelChoiceField, Select

#This ModelForm is made to create a new IOC
class NewIOCForm(forms.ModelForm):
    class Meta:
        model = IOC
        fields = ('name','value','context', 'linkedInvestigation')
        widgets = {
             'name': TextInput(attrs={'class':'form-control','placeholder': 'Usually the threat name','required':'""'}),
             'value': Textarea(attrs={"class":"form-control", "rows":"4", "required":"", 'placeholder': 'What to look for'}),
             'context' : TextInput(attrs={'class':'form-control','rows':"4",'placeholder':'Context to qualify the IOC','required':'""'}),
             'linkedInvestigation': Select(attrs={'class': 'form-control'}),
         }
#This form is used when editing or deleting an IOC
class ManageIOC(forms.Form):
     ioc_id = forms.CharField(max_length=100, widget=forms.TextInput(attrs={
        'class': 'd-none',}))

class SaveCustomIOC(forms.ModelForm):
    ioc_id = forms.CharField(max_length=100, widget=forms.TextInput(attrs={
       'class': 'd-none','value':'a'}))
    class Meta:
        model = IOC
        fields = ('name','value','context', 'linkedInvestigation')
        widgets = {
        'name': TextInput(attrs={'class':'form-control','placeholder': 'Usually the threat name','required':'""'}),
        'value': Textarea(attrs={"class":"form-control", "rows":"4", "required":"", 'placeholder': 'What to look for'}),
        'context' : TextInput(attrs={'class':'form-control','rows':"4",'placeholder':'Context to qualify the IOC','required':'""'}),
        'linkedInvestigation': Select(attrs={'class': 'form-control'}),
        }
