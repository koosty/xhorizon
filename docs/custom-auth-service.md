# Custom auth service: game and launcher contract

Status: the service is implemented in `../horizon-account-server` (SvelteKit on Cloudflare Workers).
Its design doc, `custom-auth-service.md` in that repo, is the source of truth for the service: accounts,
Google sign-in, storage, signing keys, limits, operator endpoints, and risks. This file keeps only
what the launcher and game depend on. Game and launcher plan: [auth-providers.md](auth-providers.md).

## Decisions

| ID | Decision |
|---|---|
| D5 | Custom chat keys are issued by the custom service and signed by a key it publishes at `getPublicKeys`. `enforce-secure-profile` stays on. |
| D14 | `GET /` serves one document: spec metadata plus the `discovery` tree the game reads. The spec does not forbid extra keys. |
| D16 | Texture URLs end in the texture's SHA-256 hash. Texture hosts come from `skinDomains`, with the spec's matching rules. The game refuses a `*` rule, which disables the allowlist. |
| D20 | Chat key timing. The game asks for a new pair once `refreshedAfter` passes, checked each tick, with an hourly retry after a failure (`auth.rs:347-348`, `auth.rs:448`). Receivers accept a player's chat for 8 hours past expiry (`secure_chat.rs:353-354`). |
| D22 | Discovery: `oauth.authorize` and `oauth.token` are endpoints in the `GET /` tree. The launcher reads them from there. |
| D23 | Public client, `client_id` `horizon-launcher`, no secret. Redirect `http://127.0.0.1:<port>/callback` (RFC 8252 7.3): the service accepts any port on exactly `127.0.0.1`. |
| D25 | Scope `minecraft`. No OAuth refresh token: the Yggdrasil `refresh` renews the access token. An access token unused past its 15-day lifetime needs a new browser sign-in. |
| D27 | Token response: JSON, `Cache-Control: no-store`, with `access_token`, `token_type`, `expires_in` and `selectedProfile` (the spec's profile object). Errors use RFC 6749 names. |
| D28 | Custom error names: `ForbiddenOperationException` (invalid session, 403), `multiplayer.access.banned` (banned, 403), `InsufficientPrivilegesException` (multiplayer off, 403), and 5xx (unavailable). The game shows the rest raw, so the service sends English `errorMessage` text for them. |
| D29 | The service never sends `FORCED_NAME_CHANGE`: player renames are forbidden, and operator renames are out of scope. |
| D33 | `meta.horizonAuth` is an integer in the `GET /` `meta` object, 1 for this contract. An absent value means 1. The game, the launcher and the server refuse a value above what they support, with `horizon.auth.service_too_new`. The value goes up only for an incompatible wire change. |

## Endpoints

The game and launcher call these. "Served" is the status in `../horizon-account-server/README.md`.

| Discovery entry | Path | Used by | Served |
|---|---|---|---|
| `GET /` | `/` | game, server, launcher | yes |
| `session.join` | `/sessionserver/session/minecraft/join` | game | no (handoff 12) |
| `session.verify` | `/sessionserver/session/minecraft/hasJoined` | server | no (handoff 12) |
| `session.getProfileById` | `/sessionserver/session/minecraft/profile/{profileId}` | game, server | yes |
| `profiles.getByName` | `/users/profiles/minecraft/{name}` | game | no (handoff 12) |
| `authentication.getPublicKeys` | `/authentication/getPublicKeys` | game, server | yes |
| `player.getCertificates` | `/minecraftservices/player/certificates` | game | yes |
| `player.getAttributes` | `/minecraftservices/player/attributes` | game | no (handoff 12) |
| `oauth.authorize` | `/oauth/authorize` | launcher (browser) | yes |
| `oauth.token` | `/oauth/token` | launcher | yes |
| `authserver/refresh`, `validate`, `invalidate`, `signout` | `/authserver/...` | launcher | yes |

Discovery advertises the four "no" rows. Until they are served, a custom join fails with a 404.

## Sign-in

- The launcher's messages for sign-in errors are in auth-providers.md (Launcher, Custom sign-in).
- Redirect and code rules are the service's, in its own doc: loopback host `127.0.0.1` on any port,
  60-second single-use codes, PKCE S256 only, and no refresh token (D23, D25).
- `oauth.token` takes a form POST and rejects a cross-origin `Origin`. The launcher sends the service origin.

## Wire format

Fixed by the game and server code.

- Discovery: `{"discovery": {"<service>": {"endpoints": {"<name>": {"uri": "..."}}}}}`. Services: `session` (`join`, `verify`, `getProfileById`), `profiles` (`getByName`, a template with `{name}`, lowercased), `authentication` (`getPublicKeys`), `player` (`getCertificates`, `getAttributes`), `oauth` (`authorize`, `token`).
- Join body: `accessToken`, `selectedProfile` (32 hex digits, no dashes), `serverId`.
- `hasJoined`: query `username` and `serverId`, plus `ip` when the server prevents proxies (`auth.rs:570-584`). Success is 200 with the profile. Failure is 204.
- Name lookup: 200 with `{"id", "name"}`, or 204 for an unknown name.
- Profile by UUID: signed by default. `unsigned=false` for textures (`profiles.rs:67`). `unsigned=true` for ban and action data (`auth.rs:253`).
- Key set: `playerCertificateKeys`, a list of `{"publicKey": base64 DER}`. One bad key fails the whole answer. An absent `profilePropertyKeys` counts as empty (`profiles.rs:123`).
- Chat key: `publicKey` and `privateKey` (PEM), `publicKeySignatureV2` (the signature the game uses, `auth.rs:411`), `expiresAt` and `refreshedAfter` (ISO 8601, `auth.rs:415`, `auth.rs:419`).
- Token response: D27.
- Errors: the spec's shape, `{"error", "errorMessage", "cause"}`. The game maps on `error` and on HTTP 401 and 5xx (`auth.rs:153-170`). Custom errors use the names in D28. Other `error` values show `errorMessage` raw.

## Textures

- Skins and capes are PNG, served at `/textures/{hash}` (D16). A new skin has a new URL, so the disk cache never serves an old one.
- Textures are signed with the key in `signaturePublickey` from `GET /`. The game verifies that signature (D19 in auth-providers.md).

## Ban and action data

Read on the title screen (`auth.rs:232-260`).

- `player/getAttributes` gives `privileges.multiplayerServer.enabled` and `banStatus.bannedScopes.MULTIPLAYER`, with `expires` (ISO 8601, absent means permanent), `reason` and `reasonMessage` (`ban_notice.rs:206-222`).
- `profile/{uuid}?unsigned=true` gives `profileActions` (`ban_notice.rs:229-244`).

`meta` carries `"feature.enable_profile_key": true` when chat keys are on.

## Consequence

A vanilla client or server does not accept a custom session unless authlib-injector runs on it.
`custom` mode works between Horizon clients and Horizon servers only.

## Open

A7. Legal review. The Yggdrasil spec is unofficial and CC BY-SA 4.0: implement its behaviour, do not
copy its text.
