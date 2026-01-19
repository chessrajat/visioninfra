from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from .models import User


class AuthenticationFlowTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_register_and_login_password(self):
        payload = {
            "username": "jdoe",
            "email": "jdoe@example.com",
            "phone": "+15551234567",
            "full_name": "Jane Doe",
            "designation": "Analyst",
            "department": "Ops",
            "password": "StrongPass#123",
        }
        response = self.client.post(reverse("auth-register"), payload, format="json")
        self.assertEqual(response.status_code, 201)

        login_response = self.client.post(
            reverse("auth-login"),
            {"identifier": "jdoe", "password": "StrongPass#123"},
            format="json",
        )
        self.assertIn(login_response.status_code, {200, 428, 202})

    def test_otp_request_and_verify(self):
        user = User.objects.create_user(
            username="otpuser",
            email="otp@example.com",
            full_name="OTP User",
            password="StrongPass#123",
        )
        user.must_change_password = False
        user.save()
        response = self.client.post(
            reverse("auth-otp-request"),
            {"identifier": "otpuser", "channel": "sms"},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        otp_code = response.data.get("otp_preview")
        verify_response = self.client.post(
            reverse("auth-otp-verify"),
            {"identifier": "otpuser", "channel": "sms", "code": otp_code},
            format="json",
        )
        self.assertEqual(verify_response.status_code, 200)
