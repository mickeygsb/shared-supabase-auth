"use client";

import { useState } from "react";
import type { SupabaseClient } from "@supabase/supabase-js";

export type AuthFlowStep = "password" | "enroll" | "challenge";

export interface UseAuthFlowOptions {
  /** A Supabase browser client the caller already created. */
  supabase: SupabaseClient;
  /** Called once when enrolling a fresh TOTP factor, to name it (e.g. `Career Manager ${date}`). */
  mfaFriendlyName: () => string;
  /** Called after a successful sign-in (password + MFA, or password alone if the app doesn't require aal2). */
  onSuccess: () => void;
}

export interface UseAuthFlowResult {
  step: AuthFlowStep;
  error: string;
  busy: boolean;
  email: string;
  setEmail: (value: string) => void;
  password: string;
  setPassword: (value: string) => void;
  code: string;
  setCode: (value: string) => void;
  qr: string | null;
  secret: string | null;
  signIn: () => Promise<void>;
  verifyCode: () => Promise<void>;
}

// Headless password -> MFA-enroll-or-challenge flow shared by every app's
// login page. Each app keeps its own JSX/styling and calls this for the
// state + Supabase calls, which used to be hand-copied (and drifting) across
// account-manager, career-manager, and task-manager.
export function useAuthFlow({ supabase, mfaFriendlyName, onSuccess }: UseAuthFlowOptions): UseAuthFlowResult {
  const [step, setStep] = useState<AuthFlowStep>("password");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [factorId, setFactorId] = useState<string | null>(null);
  const [qr, setQr] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);

  const signIn = async () => {
    if (!email || !password || busy) return;
    setBusy(true);
    setError("");
    try {
      const { error: signInError } = await supabase.auth.signInWithPassword({ email, password });
      if (signInError) {
        setError("Incorrect email or password.");
        setPassword("");
        return;
      }

      // Password alone leaves the session at aal1. Decide where to send them.
      const { data: factors, error: factorError } = await supabase.auth.mfa.listFactors();
      if (factorError) {
        setError(factorError.message);
        return;
      }

      const verified = factors?.totp?.find((f) => f.status === "verified");

      if (verified) {
        setFactorId(verified.id);
        setStep("challenge");
        return;
      }

      // No second factor yet — enroll one now rather than letting a
      // password-only session reach the app.
      const { data: enrolled, error: enrollError } = await supabase.auth.mfa.enroll({
        factorType: "totp",
        friendlyName: mfaFriendlyName(),
      });
      if (enrollError) {
        setError(enrollError.message);
        return;
      }
      setFactorId(enrolled.id);
      setQr(enrolled.totp.qr_code);
      setSecret(enrolled.totp.secret);
      setStep("enroll");
    } catch {
      setError("Network error. Try again.");
    } finally {
      setBusy(false);
    }
  };

  const verifyCode = async () => {
    if (code.length < 6 || busy || !factorId) return;
    setBusy(true);
    setError("");
    try {
      const { data: challenge, error: challengeError } =
        await supabase.auth.mfa.challenge({ factorId });
      if (challengeError) {
        setError(challengeError.message);
        return;
      }

      const { error: verifyError } = await supabase.auth.mfa.verify({
        factorId,
        challengeId: challenge.id,
        code,
      });
      if (verifyError) {
        setError("That code didn't match. Try the next one.");
        setCode("");
        return;
      }

      onSuccess();
    } catch {
      setError("Network error. Try again.");
    } finally {
      setBusy(false);
    }
  };

  return {
    step,
    error,
    busy,
    email,
    setEmail,
    password,
    setPassword,
    code,
    setCode,
    qr,
    secret,
    signIn,
    verifyCode,
  };
}
