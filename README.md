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

- Players should not need GitHub accounts.
- Developers/content creators should require both Steam and GitHub identities.
- Root developers require Steam and GitHub identities plus an assigned root
  role.

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
```

## Initial routes

```text
GET  /healthz
GET  /v1/status
GET  /v1/auth/status
POST /v1/auth/steam/ticket
POST /v1/auth/github/token
GET  /v1/admin/profiles
POST /v1/init
GET  /v1/export
GET  /admin
```

Protected routes expect:

```text
Authorization: Bearer <VAPOR_IDENTITY_ADMIN_TOKEN>
```

`GET /admin` is a small read-only dashboard protected by HTTP Basic auth using
username `root` and `VAPOR_IDENTITY_DASHBOARD_PASSWORD`. Closed pre-alpha HTTP
access is temporarily allowed before DNS is ready. Move the dashboard to HTTPS
once DNS is active.

## Auth configuration

Server-local env only:

```text
VAPOR_IDENTITY_STEAM_APP_ID=2122620
VAPOR_IDENTITY_STEAM_AUTH_IDENTITY=vapor-identity
VAPOR_IDENTITY_STEAM_WEB_API_KEY=
VAPOR_IDENTITY_GITHUB_CLIENT_ID=
```

Steam ticket verification uses Steamworks `GetAuthTicketForWebApi` on the
client and `ISteamUserAuth/AuthenticateUserTicket` on the server. GitHub
developer linking expects a GitHub Device Flow/OAuth token from a client, then
verifies it against GitHub before storing only the GitHub user id/login.

Real Steam and GitHub account linking is planned but not implemented in this
initial scaffold.

## Non-goals

- docs artifact storage;
- diagnostics bundle storage;
- homepage/legal content;
- deployment orchestration.
