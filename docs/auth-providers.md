# Authentication providers

Status: plan. Nothing here is implemented. The Mojang flow stays documented in
[microsoft-account.md](microsoft-account.md). This plan replaces its owner-gate, offline and
token-storage rules for the `mojang` provider only. The custom auth service is implemented in
`../horizon-account-server`. The game and launcher's contract with it is in
[custom-auth-service.md](custom-auth-service.md).

## Summary

- The launcher has one setting, `Authenticate With`: Mojang or Horizon Account Provider. Offline names were removed (upstream `1e789800af`).
- A dedicated server runs in one mode: `mojang`, `custom`, or `offline`.
- The owner gate applies only to the Mojang provider.
- A custom auth service, run by the operator, issues accounts, sessions, skins, capes and chat keys.

## Decisions

The service's decisions are in the server repo's `custom-auth-service.md`. The ones this plan relies
on are restated in [custom-auth-service.md](custom-auth-service.md).

| ID | Decision |
|---|---|
| D1 | Launcher-wide setting `Authenticate With`: Mojang or Horizon Account Provider. |
| D2 | Owner gate: Play is refused under Mojang when no account owns the game. Horizon Account Provider skips it. This replaces the server-mode gate discussed earlier. |
| D3 | Removed: offline names and their owner rule (upstream `1e789800af`). |
| D4 | Custom sign-in is a browser redirect to a loopback address with PKCE. The password never reaches the launcher. |
| D6 | One mode per dedicated server: `mojang`, `custom`, or `offline`. A join the server's mode can't accept fails with a message naming the setting to change. |
| D7 | Offline servers grant no ops, whitelist, or ban privileges by name or UUID. |
| D8 | Textures: the signed `textures` property is used when a profile has one. Otherwise the game falls back to a name lookup on the custom service, TLauncher-style. Both are used. |
| D9 | Name-lookup texture entries expire after 10 minutes, matching Horizon's profile cache (`skins.rs:249`). |
| D18 | Name fallback replaces D8's endpoint: `profiles/getByName` gives the UUID, then `GET /sessionserver/session/minecraft/profile/{uuid}?unsigned=false` gives the signed textures. No new endpoint. Unsigned textures would be dropped for other players (`remote.rs:5903`). |
| D19 | The game does not verify texture signatures. It checks only that a `signature` field exists (`skins.rs:212`, `skins.rs:426`). `profilePropertyKeys` is parsed and discarded (`profiles.rs:123`). Other players see only textures that carry `signature` (`remote.rs:5903`). |
| D21 | Config names. `online-mode` keeps its vanilla meaning and is the on/off switch. `horizon-auth-provider` and `horizon-auth-discovery-url` are Horizon-only keys under `[properties]`, named like `horizon-pregen` and `horizon-lod-distance`. In `server.toml`: `[server] auth_provider` and `[server] auth_discovery_url`, following `online_mode` ↔ `online-mode` (`config.rs:118`). Replaces the earlier `auth-mode` and `auth-discovery-url`, and drops the rule that refuses `online-mode`. |
| D30 | A failed `hasJoined` on a `custom` server sends `horizon.multiplayer.unverified_account`: "Could not verify your account. Check Authenticate With in the launcher." It names the setting but not the mismatch, because the server does not query the other provider. On `mojang` servers the vanilla key stays. The reconnect list never retries this key (`reconnect.rs:72-87`). |
| D31 | The dedicated server starts when the custom service is down. A refusal would stop the server during an outage that already blocks every custom join (`conn.rs:873-886`), and bring nothing back sooner. Config errors still refuse to start (D21 checks). While the keys are missing, enforcement is off (`lan/mod.rs:421`), so unsigned chat is accepted until they arrive. |
| D32 | Key fetch retries. `SecureChat::keys()` caches the first result for the process lifetime (`lan/mod.rs:413-417`), so an empty set from a failed startup fetch disables enforcement until restart. When the set is empty, a background thread re-fetches it at most once a minute (the interval `skins.rs:935` uses). The retry never runs on the chat path, because the fetch can block for 15 s (`profiles.rs:83-84`). In `custom` mode the fetch must read `horizon-auth-discovery-url`, not the environment default (`dedicated.rs:954`). The fix also changes `mojang` servers, which share this path. |

## Launcher

### Setting

- `Authenticate With` is launcher-wide. A change applies at the next Play.
- Accounts of the other providers stay on disk and are not used while the setting points elsewhere.
- Custom URL must be HTTPS. The launcher shows the host on the account and warns once when the URL
  changes.

### Accounts

- An account record stores `provider` (`mojang` or `custom`). Custom accounts also store
  `auth_base_url`. Both are public and go in `accounts.json`. Tokens never do.
- Keychain items are keyed by provider and UUID (`<provider>:<uuid>`), so two providers' accounts
  never share an item.

### Play

- Mojang: `account::launch` runs as today (`docs/microsoft-account.md:82-86`). The gate applies.
- Custom: no ownership check. The launcher renews the custom token when it has less than an hour
  left, as it does for Mojang (`docs/microsoft-account.md:116-118`).

### Custom sign-in (D4)

1. The launcher listens on `127.0.0.1` on a random port. It serves only `/callback`, and closes after the callback or after five minutes.
2. It generates a 128-bit `state` and a PKCE `code_verifier` (43 to 128 characters, RFC 7636), and derives the S256 `code_challenge`.
3. It opens the `oauth.authorize` URL from the discovery document with `response_type=code`, `client_id=horizon-launcher`, `redirect_uri=http://127.0.0.1:<port>/callback`, `code_challenge`, `code_challenge_method=S256`, `state` and `scope=minecraft`.
4. The player signs in on the custom service with Google. Google only sees the service's own callback, never the loopback address.
5. The service redirects to the loopback address with `code` and `state`, or with `error` and `error_description`. The launcher rejects a `state` mismatch.
6. The launcher POSTs form data to `oauth.token` with `grant_type=authorization_code`, `code`, `code_verifier`, `redirect_uri` and `client_id`. The client is public: no secret. The request carries `Origin` set to the service origin, or the service rejects it (see [custom-auth-service.md](custom-auth-service.md#sign-in)).
7. The response is JSON with `Cache-Control: no-store`: `access_token` (a Yggdrasil access token), `token_type`, `expires_in` and `selectedProfile` (the spec's profile object, unhyphenated `id`). The launcher stores the access token in the keychain and adds or selects the account.

The service's sign-in rules are summarized in [custom-auth-service.md](custom-auth-service.md#sign-in).

Errors, mapped in `oauth_error` (`launcher/src/account.rs:196`), which the Microsoft codes already use without collision:

| Error | Where | Launcher shows |
|---|---|---|
| `access_denied` | authorize | Sign-in was declined in the browser. |
| `invalid_grant` | token | The sign-in expired. Start again. |
| `invalid_request`, `invalid_client`, `unauthorized_client`, `unsupported_response_type`, `unsupported_grant_type` | both | The sign-in service rejected the request. |
| `server_error`, `temporarily_unavailable` | both | The sign-in service is unavailable. Try again later. |

Every string goes through `tr(...)` (`AGENTS.md`).

### Session handoff

The session file (`docs/microsoft-account.md:239-243`) gains `provider`, and `auth_base_url` for
custom accounts. `user_type` stays `msa` for Mojang and becomes `custom` for custom accounts. The
file keeps today's rules: mode 0600, created new, read once, deleted, refused after two minutes.

## Game

### Discovery

The game reads endpoints from the discovery document of the active provider. Mojang's document is
at `https://discovery.minecraftservices.com/minecraft/client`. A custom service serves a document
of the same shape, so the game keeps one code path. `HORIZON_API_DISCOVERY` already overrides the
URL (`docs/microsoft-account.md:292-294`).

The game uses these entries: `authentication` (join and the key endpoints) and `profiles/getTexture`
`validUris` (the texture hosts it may download from).

### Join

The join request is unchanged (`docs/microsoft-account.md:268-271`), sent to the active provider's
join endpoint. A Mojang session joined to a custom server fails there, not in the game: the custom
server's own `hasJoined` finds no session and disconnects the player with the mode message (D6).
The game shows that message.

### Textures

- Custom hosts are added to the texture allowlist from the custom document's `validUris`. This
  replaces the Mojang-only rule (`docs/microsoft-account.md:298-301`) for custom sessions.
- Unsigned textures never show on another player. The entity and tab-list lookup require `signed` for everyone but the local player (`remote.rs:5903`). The name fallback (D18) therefore returns a signed profile.
- The disk cache is keyed by the URL's base name (`texture_hash`, `skins.rs:653-657`) and never expires (`skins.rs:1043-1049`). Custom texture URLs end in the texture's hash (D16 in custom-auth-service.md), so a new skin gets a new key. Name-lookup entries expire after 10 minutes (D9).

### Chat

- Custom accounts sign chat with the key pair the custom service issued (D5 in custom-auth-service.md).
- The game validates chat keys against `playerCertificateKeys` from the custom document
  (`profiles.rs:95-98`).
- Offline accounts have no keys and send unsigned chat.

## Dedicated server

### Configuration

- `online-mode` keeps its vanilla meaning. `false` makes the server offline. Default `true`, which matches today (`horizon-server-files/src/properties.rs:252`).
- `horizon-auth-provider = mojang | custom` chooses the provider while `online-mode=true`. Default `mojang`. Setting it with `online-mode=false` is refused at start.
- `horizon-auth-discovery-url` is required with `custom` and refused otherwise.
- With `online-mode=false`, `enforce-secure-profile` must be `false`. The server refuses to start otherwise: offline players carry no chat key, so enforcement rejects all their chat (`secure_chat.rs:202-206`).

### Verification

- `mojang`: unchanged. `hasJoined` goes to Mojang's endpoint from its discovery document.
- `custom`: `hasJoined` goes to the custom document's endpoint with the username and `serverId`. The returned profile's UUID is the player's UUID. Chat keys come from `playerCertificateKeys`. A failed `hasJoined` sends `horizon.multiplayer.unverified_account` (D30). `mojang` keeps the vanilla `multiplayer.disconnect.unverified_username`.
- `offline`: no verification. Players are offline-mode players as today.

### Privileges (D7)

- In `offline` mode, ops, whitelist and ban entries never apply to a player, whatever name or UUID
  they claim. An offline server therefore can't use the whitelist. An operator who needs
  privileges runs `mojang` or `custom`.

### Textures

- In `custom` mode the server forwards the signed textures from `hasJoined` in the player list.
- In `mojang` mode nothing changes.
- In `offline` mode a player has no textures unless a mod sets them (`native_set_profile_property`).
- Fallback: when a profile has no signed `textures`, the game reads the profile by name (D18).

## Risks

R1. Offline mode weakens the server's identity for every player who joins it (D7).

Risks of the custom service are in `horizon-account-server/custom-auth-service.md`.

## Implementation order

Each step is a PR under the ~500-line guide in `AGENTS.md`.

1. Dedicated server: `horizon-auth-provider`, configuration checks, `custom` verification, offline privilege rule.
   Test against a mock discovery document.
2. Game: provider on the session file, per-provider discovery, custom join, texture allowlist.
3. Launcher: `Authenticate With`, provider on accounts, keychain keys, browser sign-in, provider-based
   gate.
4. Custom service: discovery, sign-in, profile, join, `hasJoined`, chat keys, skins. Separate repo.
   Implemented in `horizon-account-server`. Routes still open: handoff 12 there.
5. Docs: rewrite the owner-gate, offline and token sections of `microsoft-account.md`, add the
   `horizon-auth-provider` and `horizon-auth-discovery-url` keys to `hosting.md`, and link both
   files from `docs/README.md`.

## Tests

- Server: configuration refusals (`online-mode=false` with enforcement on, `custom` without a
  discovery URL, a provider set with `online-mode=false`). `hasJoined` mapping. Chat key signatures
  checked against a test key pair.
- Launcher: a Mojang account without an owner refuses Play. Horizon Account Provider accounts start
  without an owner. Tests go beside the existing ones in `launcher/src/account/tests.rs`.
- Game: join and rejection messages against a mock discovery document. Textures from a custom host
  load only when the host is allowed.
- Smoke run: launcher sign-in against the mock service, then a join to a `custom` server, observed
  in the game.

## Open

None in this file. The custom service's open item (A7, legal review) is in
[custom-auth-service.md](custom-auth-service.md#open).
