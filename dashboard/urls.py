from django.urls import path
from .views import home, passwords, categories, backup, settings, view_profile, logout, add_password, edit_password, delete_password, export_passwords, generate_password, save_generated_password, add_category, category_detail, restore, verify_master_password

app_name = 'dashboard'  # This sets the namespace

urlpatterns = [
    path('', home, name='home'),
    path('passwords/', passwords, name='passwords'),
    path('categories/', categories, name='categories'),
    path('backup/', backup, name='backup'),
    path('settings/', settings, name='settings'),
    path('profile/', view_profile, name='profile'),
    path('logout/', logout, name='logout'),
    path("password/add/", add_password, name="add_password"),
    path("password/edit/<int:password_id>/", edit_password, name="edit_password"),
    path("password/delete/<int:password_id>/", delete_password, name="delete_password"),
    path("password/generate_password", generate_password, name="generate_password"),
    path('password/save-password', save_generated_password, name='save_password'),
    path('password/backup/', backup, name='backup'),
     path('password/restore/', restore, name='restore_passwords'),
    path('password/export/', export_passwords, name='export_passwords'),
    path('categories/', categories, name='categores'),
    path('categories/add/', add_category, name="add_category"),
    path('categories/<int:category_id>/', category_detail, name='category_detail'),
    path('password/verify', verify_master_password, name='verify_master_password')
]
