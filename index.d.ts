import type { NextRequest, NextResponse } from "next/server";
import type { SupabaseClient } from "@supabase/supabase-js";

export declare function readAal(accessToken: string | null | undefined): string | null;

export declare function requireVerifiedUser(
  supabase: SupabaseClient
): Promise<
  | { user: NonNullable<Awaited<ReturnType<SupabaseClient["auth"]["getUser"]>>["data"]["user"]>; reason: null }
  | { user: null; reason: "unauthenticated" | "mfa_required" }
>;

export interface AuthProxyOptions {
  /** Paths (and their sub-paths) that don't require sign-in, e.g. ["/login"]. */
  publicPaths: string[];
  /** Where an unauthenticated/unverified request gets redirected. Default "/login". */
  redirectPath?: string;
  /** Require an aal2 (MFA-verified) session, not just any signed-in user. Default true. */
  requireAal2?: boolean;
  /** Append `?next=<pathname>` to the redirect so the login page can bounce back. Default false. */
  preserveNextParam?: boolean;
  /** Paths an already-authenticated user gets redirected away from (to "/"), e.g. ["/login"]. */
  redirectAuthenticatedFrom?: string[];
  /** How to reject an unauthorized request under /api/*: a 401 JSON body, or the same redirect as any other route. Default "json". */
  unauthorizedApiResponse?: "json" | "redirect";
}

export declare function createAuthProxy(
  options: AuthProxyOptions
): (request: NextRequest) => Promise<NextResponse>;
