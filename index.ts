import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { createServerClient } from "@supabase/ssr";
import type { SupabaseClient, User } from "@supabase/supabase-js";

// Reads the `aal` claim from an access token. getUser() has already validated
// the token against the auth server, so we only need to read the payload here.
export function readAal(accessToken: string | null | undefined): string | null {
  if (!accessToken) return null;
  try {
    const payload = accessToken.split(".")[1];
    const json = Buffer.from(payload.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString();
    return JSON.parse(json).aal ?? null;
  } catch {
    return null;
  }
}

// True if the user's app_metadata.allowed_apps includes this app. No `app`
// given (an app that hasn't opted into the shared-project model) skips the
// check entirely, so this is a no-op until a project actually shares users
// across multiple apps.
function isAllowedApp(user: User, app: string | undefined): boolean {
  if (!app) return true;
  const allowed = user.app_metadata?.allowed_apps;
  return Array.isArray(allowed) && allowed.includes(app);
}

export type RequireVerifiedUserReason = "unauthenticated" | "mfa_required" | "forbidden";

export type RequireVerifiedUserResult =
  | { user: User; reason: null }
  | { user: null; reason: RequireVerifiedUserReason };

// The single gate every protected surface goes through: signed in, allowed
// into this specific app, AND the session has cleared the second factor. A
// password-only session is aal1 and does not count. `supabase` is a
// request-scoped server client the caller already created — each app wires
// that to its own Supabase project. Pass `{ app: "accounts" }` (etc.) once
// multiple apps share one Supabase project's auth.users table, so a verified
// user from one app can't reach another app's data.
export async function requireVerifiedUser(
  supabase: SupabaseClient,
  { app }: { app?: string } = {},
): Promise<RequireVerifiedUserResult> {
  const { data: { user }, error } = await supabase.auth.getUser();
  if (error || !user) return { user: null, reason: "unauthenticated" };

  if (!isAllowedApp(user, app)) {
    return { user: null, reason: "forbidden" };
  }

  const { data: { session } } = await supabase.auth.getSession();
  if (readAal(session?.access_token) !== "aal2") {
    return { user: null, reason: "mfa_required" };
  }

  return { user, reason: null };
}

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

// Builds a Next.js proxy (middleware) function. Each app supplies its own
// public paths and redirect target; the cookie-refresh and gate logic is
// shared. `requireAal2: false` gives a signed-in-only gate (no MFA check),
// for an app that hasn't opted into the second factor yet.
export function createAuthProxy({
  publicPaths,
  redirectPath = "/login",
  requireAal2 = true,
  preserveNextParam = false,
  redirectAuthenticatedFrom = [],
  unauthorizedApiResponse = "json",
  app,
}: AuthProxyOptions): (request: NextRequest) => Promise<NextResponse> {
  return async function proxy(request: NextRequest): Promise<NextResponse> {
    const { pathname } = request.nextUrl;

    let response = NextResponse.next({ request });

    const supabase = createServerClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
      {
        cookies: {
          getAll: () => request.cookies.getAll(),
          setAll: (cookiesToSet) => {
            cookiesToSet.forEach(({ name, value }) => request.cookies.set(name, value));
            response = NextResponse.next({ request });
            cookiesToSet.forEach(({ name, value, options }) =>
              response.cookies.set(name, value, options)
            );
          },
        },
      }
    );

    // Also refreshes the session cookie as a side effect — don't remove.
    const { data: { user } } = await supabase.auth.getUser();

    if (user && redirectAuthenticatedFrom.includes(pathname)) {
      const url = request.nextUrl.clone();
      url.pathname = "/";
      url.search = "";
      return NextResponse.redirect(url);
    }

    const isPublic = publicPaths.some((p) => pathname === p || pathname.startsWith(p + "/"));
    if (isPublic) return response;

    // Figure out exactly why access is denied, not just whether — a "not
    // authorized for this app" and a "sign in again" bounce look identical to
    // a user unless the reason travels with the redirect.
    let reason: RequireVerifiedUserReason | null = "unauthenticated";
    if (user) {
      if (!isAllowedApp(user, app)) {
        reason = "forbidden";
      } else if (requireAal2) {
        const { data: { session } } = await supabase.auth.getSession();
        reason = readAal(session?.access_token) === "aal2" ? null : "mfa_required";
      } else {
        reason = null;
      }
    }

    if (reason === null) return response;

    const messages: Record<RequireVerifiedUserReason, string> = {
      unauthenticated: "Not signed in",
      forbidden: "Not authorized for this app",
      mfa_required: "Second factor required",
    };

    if (unauthorizedApiResponse === "json" && pathname.startsWith("/api/")) {
      return NextResponse.json({ error: messages[reason] }, { status: 401 });
    }

    const url = request.nextUrl.clone();
    url.pathname = redirectPath;
    url.search = "";
    url.searchParams.set("reason", reason);
    if (preserveNextParam) url.searchParams.set("next", pathname);
    return NextResponse.redirect(url);
  };
}
