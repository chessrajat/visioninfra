import uuid

from django.conf import settings
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.models import PermissionsMixin
from django.db import models
from django.utils import timezone


class Organization(models.Model):
    class OrgType(models.TextChoices):
        NHAI_HQ = "NHAI_HQ", "NHAI HQ"
        REGIONAL_OFFICE = "REGIONAL_OFFICE", "Regional Office"
        CORRIDOR_PROJECT = "CORRIDOR_PROJECT", "Corridor / Project"
        THIRD_PARTY = "THIRD_PARTY", "Third-party Service Provider"
        ENFORCEMENT = "ENFORCEMENT", "Enforcement Agency"

    name = models.CharField(max_length=255)
    org_type = models.CharField(max_length=32, choices=OrgType.choices)
    parent = models.ForeignKey(
        "self", related_name="children", on_delete=models.SET_NULL, null=True, blank=True
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"{self.name} ({self.get_org_type_display()})"


class UserManager(BaseUserManager):
    def create_user(self, username, password=None, **extra_fields):
        if not username:
            raise ValueError("Username is required")
        email = extra_fields.get("email")
        if email:
            extra_fields["email"] = self.normalize_email(email)
        user = self.model(username=username, **extra_fields)
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        user.save(using=self._db)
        return user

    def create_superuser(self, username, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(username=username, password=password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        SUSPENDED = "suspended", "Suspended"
        DISABLED = "disabled", "Disabled"

    class Role(models.TextChoices):
        ADMIN = "admin", "Admin"
        ENFORCEMENT = "enforcement", "Enforcement"
        REMOTE = "remote", "Remote"
        STANDARD = "standard", "Standard"
        SYSTEM = "system", "System"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True, null=True, blank=True)
    phone = models.CharField(max_length=20, unique=True, null=True, blank=True)
    full_name = models.CharField(max_length=255)
    designation = models.CharField(max_length=255, blank=True)
    department = models.CharField(max_length=255, blank=True)
    organization = models.ForeignKey(
        Organization, related_name="users", on_delete=models.SET_NULL, null=True, blank=True
    )
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.ACTIVE)
    role = models.CharField(max_length=16, choices=Role.choices, default=Role.STANDARD)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    must_change_password = models.BooleanField(default=True)
    password_changed_at = models.DateTimeField(null=True, blank=True)
    failed_attempts = models.PositiveIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    last_login_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = UserManager()

    USERNAME_FIELD = "username"

    def lock(self, duration_minutes: int):
        self.locked_until = timezone.now() + timezone.timedelta(minutes=duration_minutes)
        self.save(update_fields=["locked_until"])

    def is_locked(self) -> bool:
        return bool(self.locked_until and timezone.now() < self.locked_until)

    def mark_password_changed(self):
        self.password_changed_at = timezone.now()
        self.must_change_password = False
        self.save(update_fields=["password_changed_at", "must_change_password"])


class MFASettings(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    sms_enabled = models.BooleanField(default=False)
    email_enabled = models.BooleanField(default=False)
    totp_enabled = models.BooleanField(default=False)
    totp_secret = models.CharField(max_length=64, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def enabled_channels(self):
        channels = []
        if self.sms_enabled:
            channels.append("sms")
        if self.email_enabled:
            channels.append("email")
        if self.totp_enabled:
            channels.append("totp")
        return channels


class OTPChallenge(models.Model):
    class Channel(models.TextChoices):
        SMS = "sms", "SMS"
        EMAIL = "email", "Email"
        TOTP = "totp", "TOTP"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    channel = models.CharField(max_length=16, choices=Channel.choices)
    code = models.CharField(max_length=12)
    expires_at = models.DateTimeField()
    verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self) -> bool:
        return timezone.now() > self.expires_at


class PasswordHistory(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    password_hash = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)


class UserSession(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    refresh_token_hash = models.CharField(max_length=128)
    device_name = models.CharField(max_length=128, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    last_seen = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    def revoke(self):
        self.revoked_at = timezone.now()
        self.save(update_fields=["revoked_at"])


class ServiceAgent(models.Model):
    name = models.CharField(max_length=255)
    token_hash = models.CharField(max_length=128)
    ip_allowlist = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def allowlist(self):
        return [ip.strip() for ip in self.ip_allowlist.split(",") if ip.strip()]


class UserAPIToken(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    name = models.CharField(max_length=128)
    token_hash = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    def revoke(self):
        self.revoked_at = timezone.now()
        self.save(update_fields=["revoked_at"])
