# cadian-gate

Phone-style **pattern-unlock authentication** for web apps: a 6×6 unlock pattern + password + optional TOTP. The user's identity is a **keyed HMAC-SHA256 of the normalized pattern + password** — deterministic (login is an O(1) lookup) but not brute-forceable offline without the server key, and the raw pattern/password are never stored.

Alongside pattern users, the same store supports **traditional username + password accounts** (bcrypt-verified, same TOTP/backup-code second factor) — the login page offers a `USER LOGIN` tab automatically once one exists.

📖 **[Full documentation](docs/index.html)** — login methods, API reference, configuration and security model, in style.

Two packages, one version line:

| Package | Registry | What it is |
|---|---|---|
| `Miguelillo.CadianGate` | GitHub Packages (NuGet) | ASP.NET Core (net10.0) library: login/logout/config endpoints, JWT-in-cookie auth, MongoDB user store, admin users CRUD, break-glass env credentials, per-IP lockout, access audit log |
| `@miguelillo/cadian-gate-react` | GitHub Packages (npm) | React 18 components: `PatternPad`, themeable `LoginPage`, device fingerprinting, typed users-admin API client |

## Backend

```csharp
using PatternAuth;

builder.Services.AddPatternAuth(builder.Configuration, o =>
{
    // Everything defaults to the reference integration; the only hook most
    // hosts need is where the Mongo database comes from:
    o.MongoDatabaseFactory = sp => sp.GetRequiredService<MyMongoHolder>().Database;
    // o.CookieName = "my_token"; o.BasePath = "/api/auth"; o.TotpAccountName = "MY.APP"; …
});

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.MapPatternAuthEndpoints();       // /api/auth: me, config, setup-totp, login, logout
app.MapPatternAuthUsersEndpoints();  // /api/users: list, create, delete, new-totp-secret
```

Configuration values (key names are overridable via options):

| Key | Purpose |
|---|---|
| `JWT_SECRET` | **Required.** Signs the session JWT; also the fallback HMAC key |
| `HOMELAB_USER_ID_KEY` | HMAC key for user identities (recommended: distinct from JWT secret) |
| `HOMELAB_PASSWORD_HASH` | bcrypt hash for the break-glass password sign-in |
| `HOMELAB_TOTP_ENABLED` / `HOMELAB_TOTP_SECRET` | TOTP for the break-glass account |
| `HOMELAB_BACKUP_CODES` | base64 of comma-joined bcrypt hashes (single-use recovery codes) |
| `HOMELAB_BREAKGLASS_ENABLED` | Force password sign-in on. Otherwise it auto-disables once ≥1 pattern user exists (and stays available at 0 users for bootstrap) |

Notes:
- **Rate limiting**: `POST /login` carries `RequireRateLimiting("login")` by default — define that policy in your host (or set `LoginRateLimitPolicy = null`).
- **Mongo optional**: without a database the store is empty, pattern/username login never matches, and break-glass stays available — handy for CI and first boot.
- Login attempts (success/invalid/locked) are audited to the `access_events` collection with an optional client fingerprint.
- **User kinds**: `POST /api/users` accepts exactly one of `pattern` (pattern user) or `username` (password user, 3–32 chars of `[a-z0-9._-]`, bcrypt at work factor 12). `GET /api/auth/config` reports `passwordLoginAvailable` so the UI knows whether to offer the tab.

## Frontend

```tsx
import { LoginPage, PatternPad, createUsersApi } from '@miguelillo/cadian-gate-react';
import '@miguelillo/cadian-gate-react/styles.css';

<LoginPage
  onAuthenticated={() => setAuthed(true)}
  title="MY.APP"
  footer={<>MY.APP v1 ● TLS ENCRYPTED</>}
/>
```

- `PatternPad` — the 6×6 drag pad (touch-hardened for iOS/WebKit; emits the dot sequence).
- `LoginPage` — full login screen: pattern / user-login / break-glass modes (tabs follow what `GET /api/auth/config` offers), TOTP digit boxes, lockout countdown, animated fingerprint panel (`showFingerprintPanel={false}` to hide, `geoLookup={false}` to skip the ipapi.co call).
- `createUsersApi()` — typed client for the users CRUD, to build your own admin UI.
- Theming: components read CSS custom properties with safe fallbacks — override `--cy`, `--red`, `--amb`, `--text-rgb`, `--bg`, `--panel-bg-rgb` (and friends) to re-skin.

## Installing from GitHub Packages

GitHub Packages requires auth **even for public packages**. Create a PAT with `read:packages`, then:

**NuGet** — `nuget.config` next to your csproj:
```xml
<configuration>
  <packageSources>
    <add key="github" value="https://nuget.pkg.github.com/miguelillo/index.json" />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
  <packageSourceCredentials>
    <github>
      <add key="Username" value="miguelillo" />
      <add key="ClearTextPassword" value="%GH_PACKAGES_TOKEN%" />
    </github>
  </packageSourceCredentials>
</configuration>
```

**npm** — `.npmrc` next to your package.json:
```
@miguelillo:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GH_PACKAGES_TOKEN}
```

Export `GH_PACKAGES_TOKEN` before `dotnet restore` / `npm install` (note: npm errors out if the env var referenced by `.npmrc` is undefined).

## Releasing

Push a tag `vX.Y.Z` — the Release workflow tests, packs and publishes **both** packages at that version using the repo's own `GITHUB_TOKEN`.

## Local development against a consumer

- **NuGet**: `dotnet pack dotnet/src/PatternAuth -o /tmp/pa-feed /p:Version=X.Y.Z-dev` then `dotnet nuget add source /tmp/pa-feed -n pa-local` in the consumer.
- **npm**: `cd js && npm run build && npm pack`, then `npm i ../cadian-gate/js/miguelillo-cadian-gate-react-X.Y.Z.tgz` in the consumer.

## Security model (summary)

- Pattern identity = `HMAC-SHA256(key, normalizedPattern + '␟' + password)`, hex — nothing recoverable server-side without the key; DB leak alone reveals no credentials.
- Password users: normalized unique username + bcrypt (work factor 12) hash; the `_id` is random, so nothing about the credential is derivable from it.
- Session = JWT (HS256) in an `HttpOnly; Secure; SameSite=Strict` cookie.
- Per-IP lockout (default 10 failures → 15 min) + optional host rate-limit policy on login.
- TOTP (±1 window) per user; single-use bcrypt backup codes.
- Break-glass env credentials auto-disable once real users exist.
