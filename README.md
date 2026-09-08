# shared-supabase-auth

Shared aal2 (MFA-verified) Supabase auth gate for the personal Next.js apps
(`account-manager`, `career-manager`, `content-manager`). Each app keeps its
own Supabase project and its own `createClient()` — this module only holds
the gate logic that used to be copy-pasted (and drifting) across them.

## Install

```bash
npm install github:mickeygsb/shared-supabase-auth
```

## Exports

- **`readAal(accessToken)`** — reads the `aal` claim off a Supabase access
  token. Returns `"aal2"`, `"aal1"`, or `null`.
- **`requireVerifiedUser(supabase)`** — for route handlers / server
  components. Takes a request-scoped Supabase server client the caller
  already created, returns `{ user, reason }` where `reason` is
  `"unauthenticated"`, `"mfa_required"`, or `null` on success.
- **`createAuthProxy(options)`** — builds a `proxy.ts` / `proxy.js` function.
  See `index.d.ts` for the full option list (public paths, redirect target,
  whether to require aal2, etc).

## Usage

```ts
// proxy.ts
import { createAuthProxy } from "shared-supabase-auth";

export const proxy = createAuthProxy({
  publicPaths: ["/login"],
  redirectPath: "/login",
});

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
```

```ts
// lib/auth.ts
import { requireVerifiedUser as _requireVerifiedUser } from "shared-supabase-auth";
import { createClient } from "@/lib/supabase/server";

export async function requireVerifiedUser() {
  const supabase = await createClient();
  return _requireVerifiedUser(supabase);
}
```

Requires `next`, `@supabase/ssr`, and `@supabase/supabase-js` in the
consuming app (peer dependencies, not bundled).
