# dashboard/forms.py
from django import forms
from django.core.exceptions import ValidationError
import re
from .models import PasswordEntry, Category


class PasswordEntryForm(forms.ModelForm):
    username = forms.CharField(
        label="Username",
        widget=forms.TextInput(
            attrs={
                "placeholder": "e.g. your@email.com",
                "class": "w-full border rounded-lg p-2 focus:outline-none focus:ring-2 focus:ring-blue-500",
            }
        ),
    )
    password = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(
            attrs={
                "placeholder": "≥8 chars, uppercase, digit, special",
                "class": "border p-2 rounded-lg w-full focus:outline-none focus:ring-2 focus:ring-blue-500",
            }
        ),
    )

    class Meta:
        model = PasswordEntry
        fields = ["website", "category"]
        widgets = {
            "website": forms.TextInput(
                attrs={
                    "placeholder": "e.g. example.com",
                    "class": "w-full border rounded-lg p-2 focus:outline-none focus:ring-2 focus:ring-blue-500",
                }
            ),
            "category": forms.Select(
                attrs={
                    "class": "w-full border rounded-lg p-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                }
            ),
        }

    def clean_password(self):
        pw = self.cleaned_data.get("password", "")
        if len(pw) < 8:
            raise ValidationError("At least 8 characters.")
        if not re.search(r"[A-Z]", pw):
            raise ValidationError("Must include an uppercase letter.")
        if not re.search(r"[a-z]", pw):
            raise ValidationError("Must include a lowercase letter.")
        if not re.search(r"\d", pw):
            raise ValidationError("Must include a number.")
        if not re.search(r"[@$!%*?&]", pw):
            raise ValidationError("Must include a special character.")
        return pw

    def save(self, user=None, commit=True):
        entry = super().save(commit=False)
        if user is None:
            raise RuntimeError("PasswordEntryForm.save() requires a user argument")
        entry.user = user
        entry.username = self.cleaned_data["username"]
        entry.password = self.cleaned_data["password"]
        if commit:
            entry.save()
        return entry


class CategoryForm(forms.ModelForm):
    class Meta:
        model = Category
        fields = ["name", "description"]