from django import forms 
from .models import *

class UploadFileForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = ('title', 'file', 'date')

class EditFileForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = ('file', 'date')
    
class ForgotPasswordForm(forms.Form):
    email = forms.EmailField()

class ResetPasswordForm(forms.Form):
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)

class SimpleForm(forms.Form):
    firstName = forms.CharField(max_length=100)
    middleName = forms.CharField(max_length=100, required=False)
    lastName = forms.CharField(max_length=100)
    dob = forms.DateField(widget=forms.DateInput(attrs={'type': 'date'}))
    gender = forms.ChoiceField(choices=[('M', 'Male'), ('F', 'Female')])
    motherName = forms.CharField(max_length=100)
    fatherName = forms.CharField(max_length=100)
    aadhaarNumber = forms.CharField(max_length=12)
    contactNumber = forms.CharField(max_length=10)
    panNumber = forms.CharField(max_length=10)
