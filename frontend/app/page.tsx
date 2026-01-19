"use client";

import { useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { useAuthStore } from "@/store/auth-store";

export default function Home() {
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [otpChannel, setOtpChannel] = useState("sms");
  const [otpCode, setOtpCode] = useState("");
  const {
    statusMessage,
    loginWithPassword,
    requestOtp,
    verifyOtp,
    fetchProfile,
    logout,
    profile,
  } = useAuthStore();

  return (
    <div className="min-h-screen bg-gradient-to-br from-sky-50 via-white to-purple-50 px-6 py-12 text-slate-900">
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-10">
        <header className="flex flex-col gap-4">
          <Badge className="w-fit bg-purple-100 text-purple-700">
            VisionInfra Authentication Suite
          </Badge>
          <h1 className="text-4xl font-semibold leading-tight tracking-tight">
            Secure identity and access for NHAI operations.
          </h1>
          <p className="max-w-2xl text-lg text-slate-600">
            Modern DRF + Next.js authentication with MFA, session control, and
            system-to-system security. Skyblue and purple tones keep the
            experience calm and trustworthy.
          </p>
        </header>

        <section className="grid gap-6 lg:grid-cols-[1.2fr_1fr]">
          <Card>
            <CardHeader>
              <CardTitle>Quick Login</CardTitle>
              <CardDescription>
                Use username, email, or mobile number with password or OTP.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <label className="text-sm font-medium text-slate-700">
                  Identifier
                </label>
                <Input
                  placeholder="username / email / phone"
                  value={identifier}
                  onChange={(event) => setIdentifier(event.target.value)}
                />
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium text-slate-700">
                  Password
                </label>
                <Input
                  type="password"
                  placeholder="********"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                />
              </div>
              <div className="flex flex-wrap gap-3">
                <Button
                  onClick={() =>
                    loginWithPassword({
                      identifier,
                      password,
                    })
                  }
                >
                  Login with Password
                </Button>
                <Button
                  variant="secondary"
                  onClick={() => requestOtp({ identifier, channel: otpChannel })}
                >
                  Request OTP
                </Button>
              </div>
              <div className="grid gap-3 md:grid-cols-[0.6fr_1fr]">
                <div className="space-y-2">
                  <label className="text-sm font-medium text-slate-700">
                    OTP Channel
                  </label>
                  <select
                    className="h-11 w-full rounded-2xl border border-slate-200 bg-white/80 px-4 text-sm"
                    value={otpChannel}
                    onChange={(event) => setOtpChannel(event.target.value)}
                  >
                    <option value="sms">SMS</option>
                    <option value="email">Email</option>
                    <option value="totp">TOTP</option>
                  </select>
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium text-slate-700">
                    OTP Code
                  </label>
                  <Input
                    placeholder="123456"
                    value={otpCode}
                    onChange={(event) => setOtpCode(event.target.value)}
                  />
                </div>
              </div>
              <Button
                variant="ghost"
                className="w-full rounded-2xl border border-slate-200"
                onClick={() =>
                  verifyOtp({ identifier, channel: otpChannel, code: otpCode })
                }
              >
                Verify OTP & Sign In
              </Button>
            </CardContent>
            <CardFooter>
              <p className="text-sm text-slate-600">{statusMessage}</p>
            </CardFooter>
          </Card>

          <Card className="border border-purple-100">
            <CardHeader>
              <CardTitle>Active Session</CardTitle>
              <CardDescription>
                Manage profile, refresh sessions, and device controls.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <pre className="whitespace-pre-wrap rounded-2xl bg-slate-50 px-4 py-3 text-sm text-slate-600">
                {profile
                  ? JSON.stringify(profile, null, 2)
                  : "No profile loaded yet."}
              </pre>
              <div className="flex flex-wrap gap-3">
                <Button variant="secondary" onClick={fetchProfile}>
                  Load Profile
                </Button>
                <Button variant="ghost" onClick={logout}>
                  Sign Out
                </Button>
              </div>
            </CardContent>
          </Card>
        </section>

        <section className="grid gap-6 md:grid-cols-3">
          {[
            {
              title: "Identity & Hierarchy",
              detail:
                "Custom user profiles with role-based enforcement and organization mapping.",
            },
            {
              title: "MFA Everywhere",
              detail:
                "SMS, Email, and TOTP channels with enforced routes for sensitive roles.",
            },
            {
              title: "Session Control",
              detail:
                "JWT access, refresh rotation, and manual revocation with device tracking.",
            },
          ].map((item) => (
            <Card key={item.title} className="bg-white/70">
              <CardHeader>
                <CardTitle className="text-lg">{item.title}</CardTitle>
                <CardDescription>{item.detail}</CardDescription>
              </CardHeader>
            </Card>
          ))}
        </section>
      </div>
    </div>
  );
}
