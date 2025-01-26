from django import forms
from django.conf import settings

AUTH = settings.TWO_FACTOR_AUTH

class OTPVerificationForm(forms.Form):
    otp = forms.CharField(
        max_length = AUTH.get("OTP", {}).get("MAX_NUMBER", 6),
        widget=forms.TextInput(attrs={"class": "form-control","placeholder": "Enter OTP"}),
        label="One-Time Password",
    )


class ForgotForm(forms.Form):
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            "class": "form-control",
            "placeholder": "Enter your email",
            "required": True
        }),
    )


class ResetUserName(forms.Form):
    username = forms.CharField(
        widget=forms.TextInput(attrs={"class": "form-control","placeholder": "username"}),
        label="Username",
    )


class ResetPassword(forms.Form):
    new_password = forms.CharField(
        widget=forms.PasswordInput(attrs={"class": "form-control", "placeholder": "Enter new password"}),
        label="New Password",
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={"class": "form-control", "placeholder": "Confirm new password"}),
        label="Confirm Password",
    )

    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get("new_password")
        confirm_password = cleaned_data.get("confirm_password")

        # Check if passwords match
        if new_password and confirm_password:
            if new_password != confirm_password:
                raise forms.ValidationError("The passwords do not match.")

        return cleaned_data