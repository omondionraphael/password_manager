import re
from django.db import models
from django.contrib.auth.models import User
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from django.core.exceptions import ValidationError
import base64
import os

# Generate a key for encryption (store this securely!)
SECRET_KEY = base64.urlsafe_b64encode(os.urandom(32))

def validate_password_strength(password):
    """Enforces strong password rules"""
    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters long.")
    if not re.search(r"[A-Z]", password):
        raise ValidationError("Password must contain at least one uppercase letter.")
    if not re.search(r"\d", password):
        raise ValidationError("Password must contain at least one number.")
    if not re.search(r"[@$!%*?&]", password):
        raise ValidationError("Password must contain at least one special character.")

class PasswordEntry(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    website = models.CharField(max_length=255)
    username = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    strength = models.CharField(
        max_length=10, choices=[("weak", "Weak"), ("strong", "Strong")], default="weak"
    )
    is_reused = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    encrypted_password = models.BinaryField(default=b"", blank=False)
    category = models.ForeignKey(
        'Category',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="password_entries"  # Explicit reverse relation name
    )

    def save(self, *args, **kwargs):
        validate_password_strength(self.password)  # Validate before saving
        super().save(*args, **kwargs)

    def check_password_strength(self):
        if len(self.password) < 8 or not re.search(r"\d", self.password) or not re.search(r"[A-Z]", self.password):
            return "weak"
        return "strong"
    
    def set_password(self, raw_password):
        cipher = AES.new(SECRET_KEY, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(raw_password.encode())
        self.encrypted_password = base64.b64encode(cipher.nonce + tag + ciphertext)

    def get_password(self):
        data = base64.b64decode(self.encrypted_password)
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
        cipher = AES.new(SECRET_KEY, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()

    def __str__(self):
        return f"{self.website} - {self.username}"


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    master_password_hash = models.CharField(max_length=128)

    def set_master_password(self, raw_password):
        self.master_password_hash = make_password(raw_password)

    def check_master_password(self, raw_password):
        return check_password(raw_password, self.master_password_hash)
    
class Category(models.Model):
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True, null=True)

    def password_count(self):
        # Returns the number of PasswordEntry objects linked to this category.
       return self.password_entries.count()

    def __str__(self):
        return self.name