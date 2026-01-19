from django.contrib.auth.password_validation import validate_password
from django.utils import timezone
from rest_framework import serializers

from .models import (
    MFASettings,
    OTPChallenge,
    Organization,
    PasswordHistory,
    ServiceAgent,
    User,
    UserAPIToken,
    UserSession,
)


class OrganizationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = ["id", "name", "org_type", "parent_id"]


class UserProfileSerializer(serializers.ModelSerializer):
    organization = OrganizationSerializer(read_only=True)

    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "email",
            "phone",
            "full_name",
            "designation",
            "department",
            "organization",
            "status",
            "role",
            "must_change_password",
            "password_changed_at",
        ]


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = [
            "username",
            "email",
            "phone",
            "full_name",
            "designation",
            "department",
            "organization",
            "role",
            "password",
        ]

    def validate_password(self, value):
        validate_password(value)
        return value

    def create(self, validated_data):
        password = validated_data.pop("password")
        user = User.objects.create_user(**validated_data)
        user.set_password(password)
        user.must_change_password = True
        user.password_changed_at = timezone.now()
        user.save()
        PasswordHistory.objects.create(user=user, password_hash=user.password)
        return user


class PasswordChangeSerializer(serializers.Serializer):
    current_password = serializers.CharField()
    new_password = serializers.CharField()

    def validate_new_password(self, value):
        validate_password(value)
        return value


class LoginSerializer(serializers.Serializer):
    identifier = serializers.CharField()
    password = serializers.CharField()
    device_name = serializers.CharField(required=False, allow_blank=True)


class OTPRequestSerializer(serializers.Serializer):
    identifier = serializers.CharField()
    channel = serializers.ChoiceField(choices=OTPChallenge.Channel.choices)


class OTPVerifySerializer(serializers.Serializer):
    identifier = serializers.CharField()
    channel = serializers.ChoiceField(choices=OTPChallenge.Channel.choices)
    code = serializers.CharField()
    device_name = serializers.CharField(required=False, allow_blank=True)


class MFASetupSerializer(serializers.Serializer):
    channel = serializers.ChoiceField(choices=OTPChallenge.Channel.choices)


class MFAVerifySerializer(serializers.Serializer):
    code = serializers.CharField()
    channel = serializers.ChoiceField(choices=OTPChallenge.Channel.choices)


class SessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserSession
        fields = [
            "id",
            "device_name",
            "ip_address",
            "user_agent",
            "last_seen",
            "created_at",
            "revoked_at",
        ]


class SessionRevokeSerializer(serializers.Serializer):
    session_id = serializers.IntegerField()


class AgentRegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = ServiceAgent
        fields = ["id", "name", "ip_allowlist"]


class AgentVerifySerializer(serializers.Serializer):
    token = serializers.CharField()


class UserTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserAPIToken
        fields = ["id", "name", "created_at", "revoked_at"]


class UserTokenCreateSerializer(serializers.Serializer):
    name = serializers.CharField()
