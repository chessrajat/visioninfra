import secrets

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.utils import timezone
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.tokens import RefreshToken

from .models import (
    MFASettings,
    OTPChallenge,
    PasswordHistory,
    ServiceAgent,
    User,
    UserAPIToken,
    UserSession,
)
from .serializers import (
    AgentRegisterSerializer,
    AgentVerifySerializer,
    LoginSerializer,
    MFASetupSerializer,
    MFAVerifySerializer,
    OTPRequestSerializer,
    OTPVerifySerializer,
    PasswordChangeSerializer,
    RegisterSerializer,
    SessionRevokeSerializer,
    SessionSerializer,
    UserProfileSerializer,
    UserTokenCreateSerializer,
    UserTokenSerializer,
)

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
PASSWORD_EXPIRY_DAYS = 90
MAX_SESSIONS = 3


def _get_user_by_identifier(identifier: str):
    return User.objects.filter(username=identifier).first() or User.objects.filter(
        email__iexact=identifier
    ).first() or User.objects.filter(phone=identifier).first()


def _enforce_password_history(user: User, new_password: str):
    recent = PasswordHistory.objects.filter(user=user).order_by("-created_at")[:5]
    for entry in recent:
        if check_password(new_password, entry.password_hash):
            return False
    return True


def _issue_tokens(user: User, request, device_name: str = ""):
    refresh = RefreshToken.for_user(user)
    refresh_token = str(refresh)
    access_token = str(refresh.access_token)
    session = UserSession.objects.create(
        user=user,
        refresh_token_hash=make_password(refresh_token),
        device_name=device_name,
        ip_address=request.META.get("REMOTE_ADDR"),
        user_agent=request.META.get("HTTP_USER_AGENT", ""),
    )
    _limit_sessions(user, session)
    return {
        "access": access_token,
        "refresh": refresh_token,
        "session_id": session.id,
    }


def _limit_sessions(user: User, newest_session: UserSession):
    active_sessions = (
        UserSession.objects.filter(user=user, revoked_at__isnull=True)
        .exclude(id=newest_session.id)
        .order_by("created_at")
    )
    while active_sessions.count() >= MAX_SESSIONS:
        oldest = active_sessions.first()
        if not oldest:
            break
        oldest.revoke()
        active_sessions = active_sessions.exclude(id=oldest.id)


def _password_expired(user: User):
    if not user.password_changed_at:
        return True
    return user.password_changed_at + timezone.timedelta(days=PASSWORD_EXPIRY_DAYS) < timezone.now()


def _mfa_required(user: User):
    return user.role in {User.Role.ADMIN, User.Role.ENFORCEMENT, User.Role.REMOTE}


def _create_otp(user: User, channel: str):
    code = f"{secrets.randbelow(999999):06d}"
    otp = OTPChallenge.objects.create(
        user=user,
        channel=channel,
        code=code,
        expires_at=timezone.now() + timezone.timedelta(minutes=5),
    )
    return otp


class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response(UserProfileSerializer(user).data, status=status.HTTP_201_CREATED)


class LoginPasswordView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        identifier = serializer.validated_data["identifier"]
        password = serializer.validated_data["password"]
        device_name = serializer.validated_data.get("device_name", "")
        user = _get_user_by_identifier(identifier)
        if not user:
            return Response({"detail": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)
        if not user.is_active or user.status != User.Status.ACTIVE:
            return Response({"detail": "Account is not active."}, status=status.HTTP_403_FORBIDDEN)
        if user.is_locked():
            return Response(
                {"detail": "Account is locked. Try later."}, status=status.HTTP_423_LOCKED
            )
        if not user.check_password(password):
            user.failed_attempts += 1
            if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
                user.lock(LOCKOUT_MINUTES)
            user.save(update_fields=["failed_attempts"])
            return Response({"detail": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)
        user.failed_attempts = 0
        user.locked_until = None
        user.last_login_at = timezone.now()
        user.save(update_fields=["failed_attempts", "locked_until", "last_login_at"])
        if user.must_change_password or _password_expired(user):
            return Response(
                {"detail": "Password change required.", "must_change_password": True},
                status=status.HTTP_428_PRECONDITION_REQUIRED,
            )
        mfa_settings, _ = MFASettings.objects.get_or_create(user=user)
        if _mfa_required(user):
            channels = mfa_settings.enabled_channels()
            if not channels:
                return Response(
                    {
                        "detail": "MFA setup required.",
                        "mfa_setup_required": True,
                    },
                    status=status.HTTP_428_PRECONDITION_REQUIRED,
                )
            otp = _create_otp(user, channels[0])
            data = {
                "detail": "MFA required.",
                "mfa_required": True,
                "channel": otp.channel,
            }
            if settings.DEBUG:
                data["otp_preview"] = otp.code
            return Response(data, status=status.HTTP_202_ACCEPTED)
        tokens = _issue_tokens(user, request, device_name)
        return Response(tokens, status=status.HTTP_200_OK)


class OTPRequestView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = OTPRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        identifier = serializer.validated_data["identifier"]
        channel = serializer.validated_data["channel"]
        user = _get_user_by_identifier(identifier)
        if not user:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        if not user.is_active or user.status != User.Status.ACTIVE:
            return Response({"detail": "Account is not active."}, status=status.HTTP_403_FORBIDDEN)
        if user.is_locked():
            return Response(
                {"detail": "Account is locked. Try later."}, status=status.HTTP_423_LOCKED
            )
        otp = _create_otp(user, channel)
        payload = {"detail": "OTP issued.", "channel": otp.channel}
        if settings.DEBUG:
            payload["otp_preview"] = otp.code
        return Response(payload, status=status.HTTP_200_OK)


class OTPVerifyView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = OTPVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        identifier = serializer.validated_data["identifier"]
        channel = serializer.validated_data["channel"]
        code = serializer.validated_data["code"]
        device_name = serializer.validated_data.get("device_name", "")
        user = _get_user_by_identifier(identifier)
        if not user:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        if not user.is_active or user.status != User.Status.ACTIVE:
            return Response({"detail": "Account is not active."}, status=status.HTTP_403_FORBIDDEN)
        if user.is_locked():
            return Response(
                {"detail": "Account is locked. Try later."}, status=status.HTTP_423_LOCKED
            )
        if user.must_change_password or _password_expired(user):
            return Response(
                {"detail": "Password change required.", "must_change_password": True},
                status=status.HTTP_428_PRECONDITION_REQUIRED,
            )
        otp = (
            OTPChallenge.objects.filter(user=user, channel=channel, verified=False)
            .order_by("-created_at")
            .first()
        )
        if not otp or otp.is_expired() or otp.code != code:
            return Response({"detail": "Invalid or expired OTP."}, status=status.HTTP_400_BAD_REQUEST)
        otp.verified = True
        otp.save(update_fields=["verified"])
        tokens = _issue_tokens(user, request, device_name)
        return Response(tokens, status=status.HTTP_200_OK)


class TokenRefreshView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = TokenRefreshSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        refresh_token = serializer.validated_data["refresh"]
        access_token = serializer.validated_data["access"]
        session = None
        for candidate in UserSession.objects.filter(revoked_at__isnull=True):
            if check_password(refresh_token, candidate.refresh_token_hash):
                session = candidate
                break
        if not session:
            return Response({"detail": "Session not found."}, status=status.HTTP_404_NOT_FOUND)
        session.refresh_token_hash = make_password(refresh_token)
        session.save(update_fields=["refresh_token_hash"])
        return Response({"access": access_token, "refresh": refresh_token})


class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        refresh = request.data.get("refresh")
        if refresh:
            for session in UserSession.objects.filter(user=request.user, revoked_at__isnull=True):
                if check_password(refresh, session.refresh_token_hash):
                    session.revoke()
                    return Response(status=status.HTTP_204_NO_CONTENT)
        UserSession.objects.filter(user=request.user, revoked_at__isnull=True).update(
            revoked_at=timezone.now()
        )
        return Response(status=status.HTTP_204_NO_CONTENT)


class ProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        return Response(UserProfileSerializer(request.user).data)


class PasswordChangeView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = PasswordChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        current = serializer.validated_data["current_password"]
        new = serializer.validated_data["new_password"]
        if not request.user.check_password(current):
            return Response({"detail": "Current password incorrect."}, status=status.HTTP_400_BAD_REQUEST)
        if not _enforce_password_history(request.user, new):
            return Response(
                {"detail": "Password was used recently."}, status=status.HTTP_400_BAD_REQUEST
            )
        request.user.set_password(new)
        request.user.mark_password_changed()
        PasswordHistory.objects.create(user=request.user, password_hash=request.user.password)
        return Response({"detail": "Password changed."})


class MFASetupView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = MFASetupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        channel = serializer.validated_data["channel"]
        settings_obj, _ = MFASettings.objects.get_or_create(user=request.user)
        if channel == OTPChallenge.Channel.SMS:
            settings_obj.sms_enabled = True
        elif channel == OTPChallenge.Channel.EMAIL:
            settings_obj.email_enabled = True
        else:
            settings_obj.totp_enabled = True
            settings_obj.totp_secret = secrets.token_hex(16)
        settings_obj.save()
        data = {"detail": "MFA enabled.", "channel": channel}
        if channel == OTPChallenge.Channel.TOTP:
            data["totp_secret"] = settings_obj.totp_secret
        return Response(data)


class MFAVerifyView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = MFAVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        channel = serializer.validated_data["channel"]
        code = serializer.validated_data["code"]
        otp = (
            OTPChallenge.objects.filter(user=request.user, channel=channel, verified=False)
            .order_by("-created_at")
            .first()
        )
        if not otp or otp.is_expired() or otp.code != code:
            return Response({"detail": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)
        otp.verified = True
        otp.save(update_fields=["verified"])
        return Response({"detail": "MFA verified."})


class SessionListView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        sessions = UserSession.objects.filter(user=request.user).order_by("-created_at")
        return Response(SessionSerializer(sessions, many=True).data)


class SessionRevokeView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = SessionRevokeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        session_id = serializer.validated_data["session_id"]
        session = UserSession.objects.filter(user=request.user, id=session_id).first()
        if not session:
            return Response({"detail": "Session not found."}, status=status.HTTP_404_NOT_FOUND)
        session.revoke()
        return Response({"detail": "Session revoked."})


class AgentRegisterView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        if request.user.role != User.Role.ADMIN:
            return Response({"detail": "Admin only."}, status=status.HTTP_403_FORBIDDEN)
        serializer = AgentRegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        raw_token = secrets.token_hex(24)
        agent = serializer.save(token_hash=make_password(raw_token))
        return Response(
            {"id": agent.id, "name": agent.name, "token": raw_token},
            status=status.HTTP_201_CREATED,
        )


class AgentVerifyView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = AgentVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data["token"]
        ip = request.META.get("REMOTE_ADDR")
        for agent in ServiceAgent.objects.filter(is_active=True):
            if check_password(token, agent.token_hash):
                if agent.allowlist() and ip not in agent.allowlist():
                    return Response({"detail": "IP not allowed."}, status=status.HTTP_403_FORBIDDEN)
                return Response({"detail": "Agent verified.", "agent": agent.name})
        return Response({"detail": "Invalid token."}, status=status.HTTP_401_UNAUTHORIZED)


class UserTokenListCreateView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        tokens = UserAPIToken.objects.filter(user=request.user)
        return Response(UserTokenSerializer(tokens, many=True).data)

    def post(self, request):
        serializer = UserTokenCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        raw_token = secrets.token_hex(24)
        token = UserAPIToken.objects.create(
            user=request.user,
            name=serializer.validated_data["name"],
            token_hash=make_password(raw_token),
        )
        return Response(
            {"id": token.id, "name": token.name, "token": raw_token},
            status=status.HTTP_201_CREATED,
        )
