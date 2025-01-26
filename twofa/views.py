import random
from urllib.parse import urlparse
import base64
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import redirect, render
from django.views.generic import FormView, TemplateView, CreateView
from django.http import HttpResponse
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.core.exceptions import ObjectDoesNotExist
from django.core.mail import send_mail
from django.http import HttpResponse
from django.conf import settings
import uuid
from django.utils.module_loading import import_string
from .forms import ForgotForm, OTPVerificationForm, ResetPassword, ResetUserName
from .tasks import TimedKeyFernet

timed_fernet = TimedKeyFernet()

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
    template_name = "twofa/v2/login.html"
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
                return redirect(AUTH["LOGIN_REDIRECT"] or "/")  # Redirect to post-login page
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
    template_name = "twofa/v2/send_otp.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        try:

            # Generate a unique identifier with characters and numbers
            unique_id = str(uuid.uuid4())

            full_url = self.request.build_absolute_uri()
            parsed_url = urlparse(full_url)
            id = self.request.session.get('id')
            email = self.request.session.get('email')
            otp_url = f"{parsed_url.scheme}://{parsed_url.netloc}/verify/{id}/{unique_id}"

            context["qr_code_url"] = f"https://api.qrserver.com/v1/create-qr-code/?data={otp_url}&size=200x200"
            context["otp_url"] = otp_url
            context["email"] = email

            del self.request.session['id']

        except KeyError:
            context = {
                "exception" : True
            }

        return context


class Verify2FAView(FormView):
    """
    Handles OTP verification.
    """    
    template_name = "twofa/v2/verify.html"
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
        try:
            self.generate_otp()  # Generate and store OTP in the session
            context = {
                "form" : OTPVerificationForm,
                "login_redirect": AUTH["LOGIN_REDIRECT"]
            }
        except KeyError:
            context = {
                "exception" : True
            }
        return render(self.request, self.template_name, context)

    def form_valid(self, form):
        """
        Handle form submission for OTP verification.
        """
        otp = form.cleaned_data["otp"]
        id = self.kwargs.get("id")
        uuid = self.kwargs.get("uuid")

        # Verify the OTP
        is_valid, message = self.verify_otp(otp)
        if is_valid:
            try:
                user = User.objects.get(id=id)
                del self.request.session['otp']
                login(self.request, user)  # Log in the user
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


class SuccessLinkView(TemplateView):
    """
    View that renders a success page after a user successfully requests a password or username reset link.
    This page informs the user that the request has been processed and a reset link has been sent to their email.
    """
    
    template_name = "twofa/v2/link_success.html"


class ForgotUsername(FormView):
    """
    View for handling the forgotten username functionality. This view allows the user to
    request a username reset link via email. The link is generated with an encrypted email
    token and sent to the user's registered email address.
    """

    template_name = "twofa/v2/forgot_username_email.html"
    form_class = ForgotForm
    success_url = "/success-link"

    def send_email_view(self, email, link):
        """
        Sends an email to the user with a username reset link.

        Args:
            email (str): The recipient email address.
            link (str): The username reset link to include in the email.

        Returns:
            HttpResponse: A response indicating whether the email was sent successfully.
        """
        subject = "Change username request"
        message = f"You can change your username via this link: {link}"
        recipient_list = [email]
        email_from = settings.EMAIL_HOST_USER

        try:
            send_mail(subject, message, email_from, recipient_list)
        except Exception as e:
            print("Error sending mail:", e)
            return HttpResponse(f"Failed to send email: {str(e)}")

    def form_valid(self, form):
        """
        Processes the valid form submission. If the user exists with the provided email, 
        an email containing the username reset link is sent.

        Args:
            form (Form): The valid form containing the user's email.

        Returns:
            HttpResponseRedirect: Redirects to the success URL after processing the form.
        """
        email = form.cleaned_data.get("email")
        user = User.objects.filter(email=email).first()

        if user:
            full_url = self.request.build_absolute_uri()
            parsed_url = urlparse(full_url)
            encrypt_value = timed_fernet.encrypt_message(email)
            value = str(encrypt_value).replace("b'", "").replace("'", "")
            url = f"{parsed_url.scheme}://{parsed_url.netloc}/reset-username/{value}"
            
            self.send_email_view(email=email, link=url)

        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        """
        Adds additional context to the template, including a custom field name.

        Args:
            **kwargs: Additional keyword arguments.

        Returns:
            dict: The context dictionary, including the default context and the custom field name.
        """
        context = super().get_context_data(**kwargs)
        context['field_name'] = "Username"
        return context


class ResetUsername(FormView):
    """
    View that handles the reset of a user's username. 
    The username is reset by validating the form and updating the user's username in the database.
    """
    
    template_name = "twofa/v2/reset_username.html"
    form_class = ResetUserName
    success_url = "/login"
    
    def get(self, request, *args, **kwargs):
        """
        Handle the GET request for resetting the username.

        This method decrypts the value passed in the URL and renders the form with the email context.

        Args:
            request (HttpRequest): The request object.
            *args: Additional positional arguments.
            **kwargs: Keyword arguments passed to the view.

        Returns:
            HttpResponse: The rendered template with the form and email context.
        """
        value = self.kwargs.get("value")
        bytes_data = value.encode("utf-8")
        try:
            decrypt_value = timed_fernet.decrypt_message(encrypted_message=bytes_data)
            context = {
                "form" : self.form_class,
                "email" : decrypt_value
            }
        except Exception:
            context = {
                "exception" : True,
            }
        return render(self.request, self.template_name, context)

    def form_valid(self, form):
        """
        Handle the valid form submission to reset the user's username.

        This method is called when the form is submitted and valid. It updates the username of the user 
        associated with the provided email.

        Args:
            form (Form): The valid form containing the new username.

        Returns:
            HttpResponseRedirect: Redirects to the success URL if the username reset is successful.
        """
        email = self.request.POST.get("email")
        username = self.request.POST.get("username")
        
        user = User.objects.get(email=email)
        user.username = username
        user.save()
        return super().form_valid(form)


class ForgotPassword(FormView):
    """
    View for handling the forgot password functionality. This view allows the user to 
    request a password reset link via email. The link is generated with an encrypted email 
    token and sent to the user's registered email address.
    """

    template_name = "twofa/v2/forgot_username_email.html"
    form_class = ForgotForm
    success_url = "/success-link"

    def send_email_view(self, email, link):
        """
        Sends an email to the user with a password reset link.

        Args:
            email (str): The recipient email address.
            link (str): The password reset link to include in the email.

        Returns:
            HttpResponse: A response indicating whether the email was sent successfully.
        """
        subject = "Change password request"
        message = f"You can change your username via this link: {link}"
        recipient_list = [email]
        email_from = settings.EMAIL_HOST_USER

        try:
            send_mail(subject, message, email_from, recipient_list)
        except Exception as e:
            print("Error sending mail:", e)
            return HttpResponse(f"Failed to send email: {str(e)}")

    def form_valid(self, form):
        """
        Processes the valid form submission. If the user exists with the provided email, 
        an email containing the password reset link is sent.

        Args:
            form (Form): The valid form containing the user's email.

        Returns:
            HttpResponseRedirect: Redirects to the success URL after processing the form.
        """
        email = form.cleaned_data.get("email")
        user = User.objects.filter(email=email).first()

        if user:
            full_url = self.request.build_absolute_uri()
            parsed_url = urlparse(full_url)
            encrypt_value = encrypt_message(email)
            value = str(encrypt_value).replace("b'", "").replace("'", "")
            url = f"{parsed_url.scheme}://{parsed_url.netloc}/reset-password/{value}"
            
            self.send_email_view(email=email, link=url)

        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        """
        Adds additional context to the template, including a custom field name.

        Args:
            **kwargs: Additional keyword arguments.

        Returns:
            dict: The context dictionary, including the default context and the custom field name.
        """
        context = super().get_context_data(**kwargs)
        context['field_name'] = "Password"
        return context


class ResetPasswordView(FormView):
    """
    View that handles the password reset process by generating a One-Time Password (OTP) 
    on GET request and resetting the user's password on POST request.
    """
    
    template_name = "twofa/v2/reset_password.html"
    form_class = ResetPassword
    success_url = "/login"
    
    def get(self, request, *args, **kwargs):
        """
        Handle the GET request for resetting the password.

        Decrypts the OTP or token passed via the URL and renders the password reset form 
        with the associated email pre-filled.

        Args:
            request (HttpRequest): The request object.
            *args: Additional positional arguments.
            **kwargs: Keyword arguments passed to the view.

        Returns:
            HttpResponse: The rendered template with the form and email context.
        """
        value = self.kwargs.get("value")
        
        try:
            # Decrypt the value safely
            decrypted_email = timed_fernet.decrypt_message(encrypted_message=value.encode("utf-8"))
            
            context = {
                "form": self.form_class(),
                "email": decrypted_email
            }
        
        except Exception:
            context = {
                "exception": True,
            }
            
        return render(self.request, self.template_name, context)

    def form_valid(self, form):
        """
        Handle the valid form submission to reset the user's password.

        This method is called when the form is submitted and is valid. It retrieves the 
        email and new password, finds the associated user, and resets their password.

        Args:
            form (Form): The valid form containing the new password.

        Returns:
            HttpResponse: Redirects to the success URL if the password reset is successful.
        """
        email = self.request.POST.get("email")
        password = self.request.POST.get("confirm_password")
        
        # Ensure user exists and reset the password
        try:
            user = User.objects.get(email=email)
            user.set_password(password)
            user.save()
        except User.DoesNotExist:
            form.add_error(None, "User not found")
            return self.form_invalid(form)
        
        return super().form_valid(form)