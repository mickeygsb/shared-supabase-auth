import type { NextRequest, NextResponse } from "next/server";
import type { SupabaseClient } from "@supabase/supabase-js";

export declare function readAal(accessToken: string | null | undefined): string | null;

export declare function requireVerifiedUser(
  supabase: SupabaseClient,
  options?: { app?: string }
): Promise<
  | { user: NonNullable<Awaited<ReturnType<SupabaseClient["auth"]["getUser"]>>["data"]["user"]>; reason: null }
  | { user: null; reason: "unauthenticated" | "mfa_required" | "forbidden" }
>;

export interface AuthProxyOptions {
  /** Paths (and their sub-paths) that don't require sign-in, e.g. ["/login"]. */
  publicPaths: string[];
  /** Where an unauthenticated/unverified request gets redirected. Default "/login".
   *  The redirect carries `?reason=unauthenticated|forbidden|mfa_required` so
   *  the login page can explain what happened instead of silently resetting. */
  redirectPath?: string;
  /** Require an aal2 (MFA-verified) session, not just any signed-in user. Default true. */
  requireAal2?: boolean;
  /** Append `?next=<pathname>` to the redirect so the login page can bounce back. Default false. */
  preserveNextParam?: boolean;
  /** Paths an already-authenticated user gets redirected away from (to "/"), e.g. ["/login"]. */
  redirectAuthenticatedFrom?: string[];
  /** How to reject an unauthorized request under /api/*: a 401 JSON body, or the same redirect as any other route. Default "json". */
  unauthorizedApiResponse?: "json" | "redirect";
  /** This app's slug. When set, a signed-in user also needs this slug in their
   *  app_metadata.allowed_apps to pass — required once multiple apps share one
   *  Supabase project's auth.users table. Omit for a single-project app. */
  app?: string;
}

export declare function createAuthProxy(
  options: AuthProxyOptions
): (request: NextRequest) => Promise<NextResponse>;
