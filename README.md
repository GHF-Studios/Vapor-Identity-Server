# Vapor Identity Server

Identity and role authority service for Vapor.

Initial implementation uses Axum/Tokio with SQLite through SQLx.

## Responsibility

- Steam identity;
- GitHub identity;
- linked Vapor developer profile;
- role assignment;
- authentication/session/JWT issuance;
- authorization source for root/developer operations.

## Identity policy direction

- A Steam account is the primary Vapor player profile anchor.
- Players should not need GitHub accounts.
- Developers/content creators should require both Steam and GitHub identities.
- Root developers require Steam and GitHub identities plus an assigned root
  role.
- `root` is a role/group on normal Steam-anchored profiles, not a separate
  account kind.

## Route

Expected public API route behind the root reverse proxy:

```text
/api/identity/
```

## State

Owns identity database state: linked accounts, roles, policy metadata, and
auth/session metadata as required.

The initial single-VPS database is SQLite, not an ad-hoc filesystem registry.
The server creates and migrates the database on startup.

Runtime environment:

```text
VAPOR_IDENTITY_BIND=127.0.0.1:7113
VAPOR_IDENTITY_STATE=/var/lib/vapor-server/identity
VAPOR_IDENTITY_DB=/var/lib/vapor-server/identity/identity.sqlite3
VAPOR_IDENTITY_ADMIN_TOKEN=<server-local secret>
VAPOR_IDENTITY_COOKIE_PATH=/
VAPOR_IDENTITY_COOKIE_SECURE=false
VAPOR_IDENTITY_PUBLIC_ORIGIN=
```

## Initial routes

```text
GET  /healthz
GET  /v1/status
GET  /v1/auth/status
POST /v1/auth/session/start
POST /v1/auth/session/steam/ticket
POST /v1/auth/session/github/token
POST /v1/auth/session/github/device/start
POST /v1/auth/session/github/device/poll
POST /v1/auth/session/finish
POST /v1/auth/steam/ticket
POST /v1/auth/github/token
GET  /v1/admin/profiles
POST /v1/admin/roles/grant
POST /v1/init
GET  /v1/export
GET  /login
GET  /login/steam
GET  /login/steam/callback
GET  /login/github
GET  /login/github/callback
GET  /logout
GET  /admin
```

Protected routes expect:

```text
Authorization: Bearer <VAPOR_IDENTITY_ADMIN_TOKEN>
```

`GET /login` is the public browser login/register page. Steam OpenID is the
browser profile creation path; it creates or resumes a Steam-anchored profile
without a Vapor username/password. GitHub browser OAuth can then link GitHub to
the current Steam profile once the GitHub app credentials are configured.

`GET /admin` is a publicly reachable dashboard shell. It does not use HTTP Basic
auth as identity authorization. It only renders privileged identity data/actions
when the request carries a non-expired Vapor identity session for a profile that
has:

- a linked Steam identity;
- a linked GitHub identity;
- an active `root` role.

Dashboard sessions currently expire after 300 seconds.

`VAPOR_IDENTITY_ADMIN_TOKEN` remains a server-local operations/bootstrap token.
It can initialize the database and grant/bootstrap the first root role, but it
is not the normal dashboard login model.

`POST /v1/admin/roles/grant` is the server-local operator route for elevated
role grants. It grants `root` or `content-developer` only when the request
provides both external identities for the same already-linked profile:

```json
{"role":"root","steam_id64":"7656119...","github_login":"example"}
{"role":"content-developer","steam_id64":"7656119...","github_login":"example"}
```

The server keeps an internal profile row to join Steam identity, GitHub
identity, sessions, roles, and audit events. That internal id is not a login
credential and is not accepted as authority for developer/root role grants.
Root/admin capability also implies content-developer capability in
authorization policy. Effective role responses include `content-developer` for
root profiles even when only the `root` row is stored.

## Auth configuration

Server-local env only:

```text
VAPOR_IDENTITY_STEAM_APP_ID=2122620
VAPOR_IDENTITY_STEAM_AUTH_IDENTITY=vapor-identity
VAPOR_IDENTITY_STEAM_WEB_API_KEY=
VAPOR_IDENTITY_GITHUB_CLIENT_ID=
VAPOR_IDENTITY_GITHUB_CLIENT_SECRET=
```

Steam ticket verification uses Steamworks `GetAuthTicketForWebApi` on the
client and `ISteamUserAuth/AuthenticateUserTicket` on the server. GitHub
developer linking expects a GitHub Device Flow/OAuth token from a client, then
verifies it against GitHub before storing only the GitHub user id/login.

Browser login uses Steam OpenID for Steam identity and GitHub OAuth web flow for
GitHub linking. Steam OpenID does not require the Steam publisher Web API key.
GitHub browser OAuth requires server-local client ID and client secret.

## Steam authority model

Vapor intentionally separates Steam identity from Steam publishing authority:

- Steam OpenID proves browser account identity and gives the SteamID64 used as
  the Vapor player profile anchor.
- Steamworks Web API tickets prove an in-Steam client/session identity to the
  backend. Server-side verification uses Steam WebAPI and app/publisher
  credentials.
- Steam ownership checks and publisher-scope checks belong to developer/root
  authorization paths, not normal player login.
- Workshop/app publishing is a separate privileged operation. A Vapor `root`
  role can authorize the Vapor-side action, but Steam-side publishing still
  needs the appropriate Steamworks/pipeline authority.

The current session flow is:

1. `POST /v1/auth/session/start` creates a 5-minute auth attempt.
2. `POST /v1/auth/session/steam/ticket` attaches a verified Steam proof.
3. `POST /v1/auth/session/github/device/start` and
   `POST /v1/auth/session/github/device/poll`, or
   `POST /v1/auth/session/github/token`, attach a verified GitHub proof.
4. `POST /v1/auth/session/finish` links both identities into one profile and
   issues a 5-minute dashboard cookie only if that profile has `root`.

For the first root only, `finish` can set `bootstrap_first_root = true` when
called with the server-local admin token and no active root profile exists.

The legacy provider routes (`/v1/auth/steam/ticket` and
`/v1/auth/github/token`) remain available as direct verification/link probes.
They are not the dashboard authorization flow. The direct GitHub token probe
verifies GitHub identity but does not create a GitHub-only profile.

## Non-goals

- docs artifact storage;
- diagnostics bundle storage;
- homepage/legal content;
- deployment orchestration.

## Source layout

```text
src/main.rs               router/bootstrap only
src/config.rs             environment-backed config and shared constants
src/types.rs              request/response DTOs and app state
src/status_handlers.rs    health/status/init/export routes
src/admin_handlers.rs     admin profile listing and role-grant routes
src/session_handlers.rs   API auth-attempt and short session flow
src/provider_handlers.rs  direct Steam/GitHub verification probes
src/browser_handlers.rs   /login, /logout, /admin browser routes
src/db.rs                 SQLite connection, migration, export counters
src/auth_attempts.rs      short-lived auth/browser attempt persistence
src/profiles.rs           Steam-anchored profiles, sessions, roles
src/providers.rs          Steam/GitHub external verification calls
src/util.rs               small shared helpers and HTML shell rendering
```
