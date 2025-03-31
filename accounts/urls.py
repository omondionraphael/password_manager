from django.urls import path
from .views import user_login, user_logout, user_register, verify_otp

app_name = "accounts"

urlpatterns = [
    path('login/', user_login, name='login'),
    path('logout/', user_logout, name='logout'),
    path('register/', user_register, name='register'),
    path('verify-otp/', verify_otp, name="verify-otp")
]
