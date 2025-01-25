import random
from urllib.parse import urlparse
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import redirect, render
from django.views.generic import FormView, TemplateView
from django.http import HttpResponse
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.core.exceptions import ObjectDoesNotExist
from django.core.mail import send_mail
from django.http import HttpResponse
from django.conf import settings
import uuid
from django.utils.module_loading import import_string
from .forms import OTPVerificationForm

User = get_user_model()
AUTH = settings.TWO_FACTOR_AUTH

class RegisterView(FormView):
    """
    Handles user registration.
    """
    template_name = "twofa/register.html"
    form_class = UserCreationForm

    def form_valid(self, form):
        user = form.save()  # Save the new user
        return HttpResponse("Registration successful! You can now log in.")


class LoginView(FormView):
    """
    Handles user login.
    """
    template_name = "twofa/login.html"
    form_class = (
        import_string(AUTH.get("FORMS", {}).get("LOGIN_FORM"))
        if AUTH.get("FORMS", {}).get("LOGIN_FORM")
        else AuthenticationForm
    )
    def form_valid(self, form):
        """
        Handle valid form submissions.
        """
        email = form.cleaned_data.get('email', None)
        username = form.cleaned_data.get('username', None)
        password = form.cleaned_data.get('password')

        # Try authenticating using username or email
        user = authenticate(self.request, username=username, password=password) or \
               authenticate(self.request, username=email, password=password)

        if user:
            if AUTH["ENABLE"]:  # Check if 2FA is enabled
                self.request.session['email'] = user.email
                self.request.session['id'] = user.id
                return redirect("twofa:setup_2fa")  # Redirect to the 2FA setup page
            else:
                login(self.request, user)  # Log in the user
                return redirect(AUTH["LOGIN_REDIRECT_URL"] or "/")  # Redirect to post-login page
        else:
            # Return an error response for invalid credentials
            return HttpResponse("Invalid credentials. Please try again.", status=401)

    def form_invalid(self, form):
        """
        Handle invalid form submissions.
        """
        return super().form_invalid(form)


class LogoutView(TemplateView):
    """
    Handles user logout.
    """
    def get(self, request, *args, **kwargs):
        logout(request)
        return redirect(AUTH.get("LOGIN_REDIRECT", "/"))


class Setup2FAView(TemplateView):
    """
    Handles the setup of Two-Factor Authentication.
    """
    template_name = "twofa/setup.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Generate a unique identifier with characters and numbers
        unique_id = str(uuid.uuid4())

        full_url = self.request.build_absolute_uri()
        parsed_url = urlparse(full_url)
        id = self.request.session.get('id')
        otp_url = f"{parsed_url.scheme}://{parsed_url.netloc}/verify/{id}/{unique_id}"

        context["qr_code_url"] = f"https://api.qrserver.com/v1/create-qr-code/?data={otp_url}&size=200x200"
        context["otp_url"] = otp_url
        del self.request.session['id']
        return context


class Verify2FAView(FormView):
    """
    Handles OTP verification.
    """    
    template_name = "twofa/v2/send_otp.html"
    form_class = OTPVerificationForm
    
    def send_email_view(request, otp, email):
        subject = "Your Two-Factor Authentication Code"
        message = f"Your OTP for logging in is: {otp}. Please do not share it with anyone."
        recipient_list = [email]
        email_from = settings.EMAIL_HOST_USER

        try:
            send_mail(subject, message, email_from, recipient_list)
        except Exception as e:
            print("Error sending mail :", e)
            return HttpResponse(f"Failed to send email: {str(e)}")

    def generate_otp(self):
        """
        Generate OTP and store it in the session.
        """
        max_length = AUTH.get("OTP", {}).get("MAX_NUMBER", 6)
        if isinstance(max_length, int) and max_length > 0:
            lower_limit = 10 ** (max_length - 1)
            upper_limit = (10 ** max_length) - 1
            otp = random.randint(lower_limit, upper_limit)
        else:
            raise ValueError("Invalid MAX_NUMBER configuration in AUTH settings.")
        email = self.request.session.get('email')

        self.request.session['otp'] = otp
        self.send_email_view(otp, email)
        del self.request.session['email']
        print("==> OTP :", otp)
        return otp

    def verify_otp(self, otp):
        """
        Verify OTP against the one stored in the session.
        """
        session_otp = self.request.session.get('otp')
        if session_otp is None:
            return False, "OTP has expired. Please request a new one."

        if str(otp) == str(session_otp):  # Cast to string for safety
            return True, "OTP verified successfully."
        return False, "Invalid OTP. Please try again."

    def get(self, request, *args, **kwargs):
        """
        Generate OTP on GET request.
        """
        self.generate_otp()  # Generate and store OTP in the session
        context = {
            "form" : OTPVerificationForm,
            "login_redirect": AUTH["LOGIN_REDIRECT"]
        }
        return render(self.request, "twofa/verify.html", context)

    def form_valid(self, form):
        """
        Handle form submission for OTP verification.
        """
        otp = form.cleaned_data["otp"]
        print("=== otp ==", otp)
        id = self.kwargs.get("id")
        uuid = self.kwargs.get("uuid")

        # Verify the OTP
        is_valid, message = self.verify_otp(otp)
        if is_valid:
            try:
                user = User.objects.get(id=id)
                del self.request.session['otp']
                login(self.request, user)  # Log in the user
                # return HttpResponse(f"Welcome!! {user.email}, You are redirecting soon on the website...")
                return redirect(AUTH["LOGIN_REDIRECT"])
            except ObjectDoesNotExist:
                return HttpResponse("User not found. Please check your details.")
        else:
            return HttpResponse(message)

    def form_invalid(self, form):
        """
        Handle invalid form submission.
        """
        return super().form_invalid(form)