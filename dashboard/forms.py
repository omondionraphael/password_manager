from django import forms
from .models import PasswordEntry, Category

class PasswordEntryForm(forms.ModelForm):
    class Meta:
        model = PasswordEntry
        fields = ["website", "username", "password", "category"]

class CategoryForm(forms.ModelForm):
    class Meta:
        model = Category
        fields = ['name', 'description']