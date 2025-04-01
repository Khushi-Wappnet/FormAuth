from django import forms
from .models import CustomUser

class RegistrationForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)
    class Meta:
        model = CustomUser
        fields = ['first_name', 'last_name', 'email', 'username', 'password', 'mobile_number']

class OTPVerificationForm(forms.Form):
    email = forms.EmailField()
    otp_code = forms.CharField(max_length=6)

class LoginForm(forms.Form):
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput)

class ForgotPasswordForm(forms.Form):
    email = forms.EmailField()

class ResetPasswordForm(forms.Form):
    email = forms.EmailField()
    otp_code = forms.CharField(max_length=6)
    new_password = forms.CharField(widget=forms.PasswordInput)