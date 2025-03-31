import random
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib import messages
from django.core.mail import send_mail
from django import forms
from django.urls import reverse
from .models import UserOTP
from django.conf import settings

# Create your views here.
def user_login(request):
    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)

        if form.is_valid():
            user = form.get_user()  # Retrieve authenticated user
            login(request, user)  # Correct way to log in user
            # send_otp_email(user)  # Send OTP on successful login
            # return redirect(reverse('accounts:verify-otp'))  # Redirect to OTP verification
            return redirect(reverse('dashboard:home'))  # Redirect to OTP verification
        else:
            messages.error(request, "Invalid username or password.")

    else:
        form = AuthenticationForm()

    return render(request, "accounts/login.html", {"form": form})

def user_logout(request):
    logout(request)
    return redirect(reverse('accounts:login'))  # Redirect to login page after logout


# Custom User Registration Form (Extends UserCreationForm)
class CustomUserCreationForm(UserCreationForm):
    email = forms.EmailField(required=True, widget=forms.EmailInput(attrs={
        "class": "w-full p-2 border rounded-lg focus:ring-2 focus:ring-blue-500",
        "placeholder": "Enter your email",
    }))

    class Meta:
        model = User
        fields = ["username", "email", "password1", "password2"]

        widgets = {
            "username": forms.TextInput(attrs={
                "class": "w-full p-2 border rounded-lg focus:ring-2 focus:ring-blue-500",
                "placeholder": "Choose a username",
            }),
            "password1": forms.PasswordInput(attrs={
                "class": "w-full p-2 border rounded-lg focus:ring-2 focus:ring-blue-500",
                "placeholder": "Create a password",
            }),
            "password2": forms.PasswordInput(attrs={
                "class": "w-full p-2 border rounded-lg focus:ring-2 focus:ring-blue-500",
                "placeholder": "Confirm your password",
            }),
        }

# Register View
def user_register(request):
    if request.method == "POST":
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)  # Auto-login after successful registration
            messages.success(request, "Account created successfully! 🎉")
            return redirect(reverse('dashboard:home'))
        else:
            messages.error(request, "Please fix the errors below.")
    else:
        form = CustomUserCreationForm()

    return render(request, "accounts/register.html", {"form": form})

def send_otp_email(user):
    otp = random.randint(100000, 999999)
    UserOTP.objects.update_or_create(user=user, defaults={"otp": otp})

    send_mail(
        "Your OTP Code",
        f"Your OTP code is {otp}. Do not share it with anyone.",
        settings.EMAIL_HOST_USER,
        [user.email],
        fail_silently=False,
    )

def verify_otp(request):
    if request.method == "POST":
        user_otp = request.POST.get("otp")
        user = request.user
        otp_obj = UserOTP.objects.filter(user=user).first()

        if otp_obj and otp_obj.otp == int(user_otp):
            messages.success(request, "2FA verification successful!")
            return redirect("dashboard:home")
        else:
            messages.error(request, "Invalid OTP. Try again.")
    
    return render(request, "accounts/verify-otp.html")