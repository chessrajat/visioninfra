from django.urls import path

from . import views

urlpatterns = [
    path("register/", views.RegisterView.as_view(), name="auth-register"),
    path("login/password/", views.LoginPasswordView.as_view(), name="auth-login"),
    path("login/otp/request/", views.OTPRequestView.as_view(), name="auth-otp-request"),
    path("login/otp/verify/", views.OTPVerifyView.as_view(), name="auth-otp-verify"),
    path("token/refresh/", views.TokenRefreshView.as_view(), name="token-refresh"),
    path("logout/", views.LogoutView.as_view(), name="auth-logout"),
    path("profile/", views.ProfileView.as_view(), name="auth-profile"),
    path("password/change/", views.PasswordChangeView.as_view(), name="auth-password-change"),
    path("mfa/setup/", views.MFASetupView.as_view(), name="auth-mfa-setup"),
    path("mfa/verify/", views.MFAVerifyView.as_view(), name="auth-mfa-verify"),
    path("sessions/", views.SessionListView.as_view(), name="auth-sessions"),
    path("sessions/revoke/", views.SessionRevokeView.as_view(), name="auth-sessions-revoke"),
    path("agents/register/", views.AgentRegisterView.as_view(), name="auth-agent-register"),
    path("agents/verify/", views.AgentVerifyView.as_view(), name="auth-agent-verify"),
    path("tokens/", views.UserTokenListCreateView.as_view(), name="auth-user-tokens"),
]
