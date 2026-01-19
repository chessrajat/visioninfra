import { create } from "zustand";

export type AuthSession = {
  access?: string;
  refresh?: string;
  sessionId?: number;
};

type AuthState = {
  session: AuthSession;
  profile: Record<string, unknown> | null;
  statusMessage: string;
  loginWithPassword: (payload: {
    identifier: string;
    password: string;
  }) => Promise<void>;
  requestOtp: (payload: { identifier: string; channel: string }) => Promise<void>;
  verifyOtp: (payload: {
    identifier: string;
    channel: string;
    code: string;
  }) => Promise<void>;
  fetchProfile: () => Promise<void>;
  logout: () => Promise<void>;
};

const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8000/api/v1/auth";

export const useAuthStore = create<AuthState>((set, get) => ({
  session: {},
  profile: null,
  statusMessage: "",
  loginWithPassword: async ({ identifier, password }) => {
    const response = await fetch(`${API_BASE}/login/password/`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ identifier, password }),
    });
    const data = await response.json();
    if (!response.ok) {
      set({ statusMessage: data.detail || "Login failed." });
      return;
    }
    if (data.access) {
      set({
        session: {
          access: data.access,
          refresh: data.refresh,
          sessionId: data.session_id,
        },
        statusMessage: "Login successful.",
      });
    } else {
      set({ statusMessage: data.detail || "Additional verification required." });
    }
  },
  requestOtp: async ({ identifier, channel }) => {
    const response = await fetch(`${API_BASE}/login/otp/request/`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ identifier, channel }),
    });
    const data = await response.json();
    set({
      statusMessage: response.ok
        ? `OTP sent (${data.channel}). ${data.otp_preview ?? ""}`
        : data.detail || "OTP request failed.",
    });
  },
  verifyOtp: async ({ identifier, channel, code }) => {
    const response = await fetch(`${API_BASE}/login/otp/verify/`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ identifier, channel, code }),
    });
    const data = await response.json();
    if (!response.ok) {
      set({ statusMessage: data.detail || "OTP verification failed." });
      return;
    }
    set({
      session: {
        access: data.access,
        refresh: data.refresh,
        sessionId: data.session_id,
      },
      statusMessage: "OTP verified. Session issued.",
    });
  },
  fetchProfile: async () => {
    const access = get().session.access;
    if (!access) return;
    const response = await fetch(`${API_BASE}/profile/`, {
      headers: { Authorization: `Bearer ${access}` },
    });
    if (!response.ok) {
      set({ statusMessage: "Unable to fetch profile." });
      return;
    }
    const data = await response.json();
    set({ profile: data, statusMessage: "Profile loaded." });
  },
  logout: async () => {
    const { refresh } = get().session;
    await fetch(`${API_BASE}/logout/`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(get().session.access
          ? { Authorization: `Bearer ${get().session.access}` }
          : {}),
      },
      body: JSON.stringify({ refresh }),
    });
    set({ session: {}, profile: null, statusMessage: "Logged out." });
  },
}));
