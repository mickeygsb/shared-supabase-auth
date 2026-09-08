import { NextResponse } from "next/server";
import { createServerClient } from "@supabase/ssr";

// Reads the `aal` claim from an access token. getUser() has already validated
// the token against the auth server, so we only need to read the payload here.
export function readAal(accessToken) {
  if (!accessToken) return null;
  try {
    const payload = accessToken.split(".")[1];
    const json = Buffer.from(payload.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString();
    return JSON.parse(json).aal ?? null;
  } catch {
    return null;
  }
}

// The single gate every protected surface goes through: signed in AND the
// session has cleared the second factor. A password-only session is aal1 and
// does not count. `supabase` is a request-scoped server client the caller
// already created — each app wires that to its own Supabase project.
export async function requireVerifiedUser(supabase) {
  const { data: { user }, error } = await supabase.auth.getUser();
  if (error || !user) return { user: null, reason: "unauthenticated" };

  const { data: { session } } = await supabase.auth.getSession();
  if (readAal(session?.access_token) !== "aal2") {
    return { user: null, reason: "mfa_required" };
  }

  return { user, reason: null };
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
} = {}) {
  return async function proxy(request) {
    const { pathname } = request.nextUrl;

    let response = NextResponse.next({ request });

    const supabase = createServerClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
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

    let allowed = false;
    if (user) {
      if (requireAal2) {
        const { data: { session } } = await supabase.auth.getSession();
        allowed = readAal(session?.access_token) === "aal2";
      } else {
        allowed = true;
      }
    }

    if (allowed) return response;

    if (unauthorizedApiResponse === "json" && pathname.startsWith("/api/")) {
      return NextResponse.json(
        { error: requireAal2 && user ? "Second factor required" : "Not signed in" },
        { status: 401 }
      );
    }

    const url = request.nextUrl.clone();
    url.pathname = redirectPath;
    url.search = "";
    if (preserveNextParam) url.searchParams.set("next", pathname);
    return NextResponse.redirect(url);
  };
}
