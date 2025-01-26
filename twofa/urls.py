from django.urls import path
from .views import (
    RegisterView, LoginView, LogoutView, 
    Setup2FAView, Verify2FAView, ForgotUsername,
    SuccessLinkView, ResetUsername, ForgotPassword,
    ResetPasswordView
)

app_name = "twofa"

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('setup/', Setup2FAView.as_view(), name='setup_2fa'),
    path('verify/<int:id>/<str:uuid>', Verify2FAView.as_view(), name='verify_2fa'),
    
    path("success-link/", SuccessLinkView.as_view(), name="success-link"),

    path("forgot-username/", ForgotUsername.as_view(), name="forgot-username"),
    path("reset-username/<str:value>", ResetUsername.as_view(), name="reset-username"),
    
    path("forgot-password/", ForgotPassword.as_view(), name="forgot-password"),
    path("reset-password/<str:value>", ResetPasswordView.as_view(), name="reset-password"),
]