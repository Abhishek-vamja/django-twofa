from django.urls import path
from .views import RegisterView, LoginView, LogoutView, Setup2FAView, Verify2FAView

app_name = "twofa"

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('setup/', Setup2FAView.as_view(), name='setup_2fa'),
    path('verify/<int:id>/<str:uuid>', Verify2FAView.as_view(), name='verify_2fa'),
]