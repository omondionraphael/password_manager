# dashboard/models.py
import binascii, base64, re
from django.db import models
from django.conf import settings
from django.contrib.auth.models import User
from Crypto.Cipher import AES


class PasswordEntry(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    website = models.CharField(max_length=255)
    _username = models.TextField(db_column="username")
    _password = models.TextField(db_column="password")
    strength = models.CharField(
        max_length=10, choices=[("weak", "Weak"), ("strong", "Strong")], default="weak"
    )
    is_reused = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    category = models.ForeignKey(
        "Category",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="password_entries",
    )

    @property
    def username(self) -> str:
        raw = self._username or ""
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8", "ignore")
        raw = raw.strip()
        pad = len(raw) % 4
        if pad:
            raw += "=" * (4 - pad)
        try:
            blob = base64.b64decode(raw)
            nonce, tag, ct = blob[:16], blob[16:32], blob[32:]
            cipher = AES.new(
                settings.PASSWORD_ENCRYPTION_KEY, AES.MODE_EAX, nonce=nonce
            )
            return cipher.decrypt_and_verify(ct, tag).decode()
        except (binascii.Error, ValueError):
            return ""

    @username.setter
    def username(self, raw: str):
        cipher = AES.new(settings.PASSWORD_ENCRYPTION_KEY, AES.MODE_EAX)
        ct, tag = cipher.encrypt_and_digest(raw.encode())
        blob = cipher.nonce + tag + ct
        self._username = base64.b64encode(blob).decode("utf-8")

    @property
    def password(self) -> str:
        raw = self._password or ""
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8", "ignore")
        raw = raw.strip()
        pad = len(raw) % 4
        if pad:
            raw += "=" * (4 - pad)
        try:
            blob = base64.b64decode(raw)
            nonce, tag, ct = blob[:16], blob[16:32], blob[32:]
            cipher = AES.new(
                settings.PASSWORD_ENCRYPTION_KEY, AES.MODE_EAX, nonce=nonce
            )
            return cipher.decrypt_and_verify(ct, tag).decode()
        except (binascii.Error, ValueError):
            return ""

    @password.setter
    def password(self, raw: str):
        cipher = AES.new(settings.PASSWORD_ENCRYPTION_KEY, AES.MODE_EAX)
        ct, tag = cipher.encrypt_and_digest(raw.encode())
        blob = cipher.nonce + tag + ct
        self._password = base64.b64encode(blob).decode("utf-8")

    @property
    def encrypted_username(self) -> str:
        """Return the raw base64‐encoded string."""
        return self._username or ""

    @property
    def encrypted_password(self) -> str:
        """Return the raw base64‐encoded string."""
        return self._password or ""

    def _str_(self):
        return f"{self.website} – {self.username}"


class Category(models.Model):
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True, null=True)

    def password_count(self):
        return self.password_entries.count()

    def _str_(self):
        return self.name