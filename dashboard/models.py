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
    def username(self) -> str: #This creates a read-only property that allows you to 
        #access the encrypted username as if it were a regular attribute
        raw = self._username or ""
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8", "ignore") #data preparation 
        raw = raw.strip() #retrive the stored username _username
        pad = len(raw) % 4
        if pad:
            raw += "=" * (4 - pad) #base 64 padding/ making it ready for decoding
        try: 
                            
                            #decryptin process. 
            blob = base64.b64decode(raw) #nonce (16 bytes): Unique value for this encryption
            nonce, tag, ct = blob[:16], blob[16:32], blob[32:] #tag (16 bytes): Authentication tag for verification
            cipher = AES.new(
                settings.PASSWORD_ENCRYPTION_KEY, AES.MODE_EAX, nonce=nonce
            ) #ct (remaining bytes): The encrypted ciphertext
            return cipher.decrypt_and_verify(ct, tag).decode()
        except (binascii.Error, ValueError):
            return ""
       
       
                                 #encryption process
    @username.setter
    def username(self, raw: str):# decorator and method defination
        cipher = AES.new(settings.PASSWORD_ENCRYPTION_KEY, AES.MODE_EAX)#To create an AES cipher object using a key from settings
        ct, tag = cipher.encrypt_and_digest(raw.encode()) #encryption process/get string/encode in cyphertext/tag to verify
        blob = cipher.nonce + tag + ct  # data combination
                                        #nouce=prevent replay attack,tag = authenticate, ct= encrypt the content
        self._username = base64.b64encode(blob).decode("utf-8")#preper the data for storage using base64 to encode. 
                                                            #stores in the privat username
    @property
    def password(self) -> str:
        raw = self._password or ""
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8", "ignore")
        raw = raw.strip()
        pad = len(raw) % 4
        if pad:                                             #same as username above 
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
        self._password = base64.b64encode(blob).decode("utf-8")             #same as username above

        #method to return the 64base to the database encryptes version to the database. 
    @property  #property getters   
    def encrypted_username(self) -> str: #allows control access to the encryted data. 
        """Return the raw base64‐encoded string."""
        return self._username or ""

    @property
    def encrypted_password(self) -> str:
        """Return the raw base64‐encoded string."""   # same as username
        return self._password or ""

    def _str_(self):
        return f"{self.website} – {self.username}"


class Category(models.Model):
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True, null=True)

    def password_count(self):
        return self.password_entries.count() # this method count the number of psswd entry 

    def _str_(self):
        return self.name 