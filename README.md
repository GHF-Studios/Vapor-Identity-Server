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

`VAPOR_IDENTITY_PUBLIC_ORIGIN` must be the exact HTTPS origin used by the
browser (scheme and host, with no trailing slash) for Identity admin form
submissions. If it is unset, those writes fail closed; request-provided Host or
forwarding headers are not accepted as the CSRF trust anchor.

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
GET  /v1/admin/audit
POST /v1/admin/roles/grant
POST /v1/admin/roles/revoke
GET  /v1/admin/permission-requests
POST /v1/admin/permission-requests
POST /v1/admin/permission-requests/{id}/approve
POST /v1/admin/permission-requests/{id}/reject
GET  /v1/admin/automation-credentials
POST /v1/admin/automation-credentials
POST /v1/init
GET  /v1/export
GET  /login
GET  /login/steam
GET  /login/steam/callback
GET  /login/github
GET  /login/github/callback
GET  /logout
GET  /admin/identity
POST /admin/identity/roles/grant
POST /admin/identity/roles/revoke
POST /admin/identity/permission-requests/{id}/approve
POST /admin/identity/permission-requests/{id}/reject
POST /admin/identity/automation-credentials
```

Protected routes expect:

```text
Authorization: Bearer <VAPOR_IDENTITY_ADMIN_TOKEN>
```

`GET /login` is the public browser login/register page. Steam OpenID is the
browser profile creation path; it creates or resumes a Steam-anchored profile
without a Vapor username/password. GitHub browser OAuth can then link GitHub to
the current Steam profile once the GitHub app credentials are configured.

`GET /admin` is owned by Vapor Platform Server and renders the shared admin
toolbench shell. Identity's service-owned section is `GET /admin/identity`; the
previous standalone Identity `/admin` page and its old form routes are removed
without redirects or compatibility aliases. The Identity section does not use
HTTP Basic auth as identity authorization. It only renders privileged identity
data/actions when the request carries a non-expired Vapor identity session for a
profile that has:

- a linked Steam identity;
- a linked GitHub identity;
- an active `root` role.

Dashboard sessions currently expire after 300 seconds.

`VAPOR_IDENTITY_ADMIN_TOKEN` remains a server-local operations/bootstrap token.
It can initialize the database and grant/bootstrap the first root role, but it
is not the normal dashboard login model.

`POST /v1/admin/roles/grant` and `/v1/admin/roles/revoke` accept either the
server-local break-glass token or a root dashboard session. A root session
creates a pending permission request; the local token remains an explicit
server-side emergency path. A request credential can only submit the matching
request kind and cannot approve, reject, or mutate roles directly.

`POST /v1/admin/permission-requests` accepts a role-change request using linked
external identities (never an internal profile id):

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

`GET /v1/admin/permission-requests` is available to root sessions and to a
request credential only for requests created with that credential. API
responses omit internal profile and credential database ids. Requests expire
after seven days; the immutable body digest binds action, role, SteamID64, and
GitHub login.

`POST /v1/admin/permission-requests/{id}/approve` and `/reject` require a current
root dashboard session, exact configured Origin, expected request version, and
explicit `confirmed: true`. Approval rechecks the linked account pair, role
state captured at request time, root-implies-developer rule, and last-root
invariant. It applies the role, updates the ticket, and writes audit records in
one SQLite transaction. Changed identity or role state marks the ticket stale.
The dashboard requires confirmation checkboxes for decisions.

The Identity dashboard creates, lists, and revokes request-only API
credentials. Their bearer secret appears once on creation; Identity stores only
its digest. Scopes are limited to `platform:deploy-request:create`,
`platform:ssh-access:request`, and `identity:role-request:create`. The SSH scope
submits access requests only; it cannot approve or activate a grant.

`POST /admin/identity/roles/grant` and `/revoke` are same-origin browser forms
that create pending requests and require an exact configured Origin.

`POST /v1/admin/roles/revoke` and `POST /admin/identity/roles/revoke` use the same
authorization and external-identity target model as grants. Revocation requires
the SteamID64 and GitHub login to resolve to the same linked profile. The
service refuses to revoke the last active `root` role so a normal dashboard/API
mistake cannot remove all root access. Because `root` implies
`content-developer`, revoking `content-developer` from an active root profile is
rejected; demote root to developer by granting an explicit `content-developer`
role first and then revoking `root`.

`GET /v1/admin/audit` returns a recent audit event listing for root/admin
operators. The listing identifies actors and subjects by linked Steam/GitHub
identities and intentionally does not expose internal profile ids.

## Auth configuration

Server-local env only:

```text
VAPOR_IDENTITY_STEAM_APP_ID=2122620
VAPOR_IDENTITY_LOOCAST_APP_ID=2122620
VAPOR_IDENTITY_STEAM_AUTH_IDENTITY=vapor-identity
VAPOR_IDENTITY_STEAM_WEB_API_KEY=
VAPOR_IDENTITY_AUTHZ_SERVICE_TOKEN=
VAPOR_IDENTITY_PLATFORM_ADMIN_AUTHZ_TOKEN=
VAPOR_IDENTITY_PLATFORM_REQUEST_AUTHZ_TOKEN=
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

`VAPOR_IDENTITY_LOOCAST_APP_ID` selects the publisher-owned Loo-Cast App ID for
server-side entitlement verification. `VAPOR_IDENTITY_AUTHZ_SERVICE_TOKEN` is
shared only with Registry, while `VAPOR_IDENTITY_PLATFORM_ADMIN_AUTHZ_TOKEN` is
shared only with Platform Server. `VAPOR_IDENTITY_PLATFORM_REQUEST_AUTHZ_TOKEN`
is a separate service-to-service token used only when Platform asks Identity
to verify a request-only deploy credential. These are distinct 64-character
hexadecimal secrets; the deploy request bearer itself is separately hashed in
Identity's database.
Identity uses the audience-specific token to protect
`POST /v1/internal/authorization/check`; that route returns only an allow/deny
decision for the current user and an allowlisted service audience. The Steam
publisher key is used server-side for configured product-license checks and is
never returned by Identity.

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
src/admin_handlers.rs     admin profile listing, role, and audit routes
src/session_handlers.rs   API auth-attempt and short session flow
src/provider_handlers.rs  direct Steam/GitHub verification probes
src/browser_handlers.rs   /login, /logout, /admin/identity browser routes
src/db.rs                 SQLite connection, migration, export counters
src/auth_attempts.rs      short-lived auth/browser attempt persistence
src/authorization_handlers.rs Identity-backed cross-service decisions
src/entitlements.rs      short-lived Steam product entitlement cache
src/profiles.rs           Steam-anchored profiles, sessions, roles
src/providers.rs          Steam/GitHub external verification calls
src/util.rs               small shared helpers and HTML shell rendering
```
