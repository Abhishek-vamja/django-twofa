from django import forms
from django.conf import settings

AUTH = settings.TWO_FACTOR_AUTH

class OTPVerificationForm(forms.Form):
    otp = forms.CharField(
        max_length = AUTH.get("OTP", {}).get("MAX_NUMBER", 6),
        widget=forms.TextInput(attrs={"class": "form-control","placeholder": "Enter OTP"}),
        label="One-Time Password",
    )
