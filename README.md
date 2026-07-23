# Vapor Identity Server

Identity and role authority service for Vapor.

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

Owns identity registry, linked accounts, roles, and auth/session metadata as
required.

## Non-goals

- docs artifact storage;
- diagnostics bundle storage;
- homepage/legal content;
- deployment orchestration.

