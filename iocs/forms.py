from django import forms
from .models import NewIOC
from django.forms import ModelForm, TextInput, Textarea, MultipleChoiceField, FileField

#This ModelForm is made to create a new IOC
class NewIOCForm(forms.ModelForm):
     class Meta:
         model = NewIOC
         fields = ('name','value','linkedInvestigation','linkedInvestigationID')
         widgets = {
             'name': TextInput(attrs={'class':'query-input','placeholder': 'Example : Conti'}),
                 'value': TextInput(attrs={'class':'query-input','placeholder':'Example : psexec'}),
                 'linkedInvestigation': TextInput(attrs={'class':'d-none'}),
                 'linkedInvestigationID': TextInput(attrs={'class':'d-none'}),
         }
#This form is made to edit or delete an IOC
class ManageIOC(forms.Form):
     id = forms.CharField(max_length=100, widget=forms.TextInput(attrs={
        'class': 'd-none',}))
     action = forms.CharField(max_length=100, widget=forms.TextInput(attrs={
        'class': 'd-none',}))
