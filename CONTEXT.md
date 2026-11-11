# Horizon

Minecraft: Java Edition 26.3 rewritten in Rust (wgpu). Authenticated by the launcher: a Mojang account that owns the game, or a Horizon Account Provider account.

## Language

**Account**:
A Minecraft profile signed in through one service: Mojang (Microsoft) or a custom auth service at an HTTPS URL.
_Avoid_: player, profile, user

**Provider**:
The service that signed an account in: Mojang, or Custom at the account's auth base URL.
_Avoid_: service, auth service, issuer

**Authenticate With**:
The launcher-wide setting naming which service signs the player in: Mojang (owner gate applies) or Horizon Account Provider (no owner gate).
_Avoid_: auth mode, sign-in method

**Session file**:
The one-shot handoff from the launcher to the game: name, UUID, token, and provider. The game reads it once and deletes it.
_Avoid_: credentials file, token file

## Architecture decisions

- **Account module owns provider resolution.** `Accounts.mode` holds the active Authenticate With value (set at construction from Settings, updated on every setting change). `can_play`, `play_as`, `session_for_game`, `launch_for_mode`, and `follow` take no mode argument. Callers ask "can I play?" — they never thread mode.
- **Provider-scoped selection.** The account module never selects an account of another service, so `NOT_THIS_SERVICE` is a guard only the module can trip, never propagated to callers.
- **Authenticate With lives in account.rs.** The mode enum, its provider mapping (`provider_for`), and the setting row are one module. `authenticate.rs` and `authenticate_row.rs` are absorbed.
- **backend.rs reads provider from the account module**, not by comparing the mode enum. Presentation copy stays with the window.
- **Tests parametrize by held state.** Each test sets `accounts.mode` at construction to cover the Mojang × Horizon Account Provider matrix; `follow()` mid-test is an explicit case.
