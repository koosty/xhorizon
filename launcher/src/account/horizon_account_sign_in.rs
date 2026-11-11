//! Custom sign-in (`docs/auth-providers.md`, "Custom sign-in"): the browser goes to the custom
//! auth service with PKCE, the service redirects to a loopback listener, and the launcher
//! exchanges the code for a token. The password never reaches the launcher.
use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The newest `meta.horizonAuth` this launcher understands (D33).
const SUPPORTED_AUTH: u64 = 1;
/// How long the loopback listener waits for the browser's redirect.
const CALLBACK_WAIT: Duration = Duration::from_secs(5 * 60);
/// The longest request line the listener reads. A callback is a few hundred bytes.
const MAX_REQUEST_LINE: u64 = 4096;
const CLIENT_ID: &str = "horizon-launcher";
/// Shown when the service's metadata is newer than this launcher.
pub const TOO_NEW: &str = "This sign-in service is newer than this launcher. Update Horizon.";
pub(super) const UNAVAILABLE: &str = "The sign-in service is unavailable. Try again later.";
const REJECTED: &str = "The sign-in service rejected the request.";
const DECLINED: &str = "Sign-in was declined in the browser.";
const EXPIRED: &str = "The sign-in expired. Start again.";
/// A custom access token's lifetime (D25): 15 days from issue or from its last renewal.
pub(super) const TOKEN_LIFETIME: u64 = 15 * 24 * 60 * 60;
/// The token is no longer good (unused past its lifetime, or revoked): sign in again.
pub(super) const HORIZON_ACCOUNT_SIGN_IN_AGAIN: &str =
    "Your sign-in expired. Sign in again in your browser.";
/// The service did not confirm a sign-out. This computer has signed out either way.
pub(super) const SIGN_OUT_UNCONFIRMED: &str = "Signed out on this computer. The sign-in service did not confirm it, so a session it gave you may still work there.";

/// The sign-in endpoints a discovery document names.
#[derive(Debug, PartialEq)]
struct Oauth {
    pub authorize: String,
    pub token: String,
}

fn uri_at(doc: &Value, name: &str) -> Option<String> {
    doc.pointer(&format!("/discovery/oauth/endpoints/{name}/uri"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// The endpoints from a `GET /` document. A service whose `meta.horizonAuth` is present but not a
/// whole number, or is above what this launcher supports, is refused.
fn oauth_endpoints(doc: &Value) -> Result<Oauth, String> {
    let auth = match doc.pointer("/meta/horizonAuth") {
        None => 1,
        Some(v) => v.as_u64().ok_or_else(|| TOO_NEW.to_owned())?,
    };
    if auth > SUPPORTED_AUTH {
        return Err(TOO_NEW.into());
    }
    match (uri_at(doc, "authorize"), uri_at(doc, "token")) {
        (Some(authorize), Some(token)) => Ok(Oauth { authorize, token }),
        _ => Err(REJECTED.into()),
    }
}

/// Reads the endpoints from the service's `GET /` document. Both endpoints must be on the same
/// origin as `base`, so the code and verifier go only to the service the player named.
fn discover(base: &str) -> Result<Oauth, String> {
    let (status, doc) = send(
        request_to("GET", &format!("{base}/")),
        None,
        "the sign-in service",
    )?;
    let oauth = match status {
        200 => oauth_endpoints(&doc)?,
        s if s >= 500 => return Err(UNAVAILABLE.into()),
        _ => return Err(REJECTED.into()),
    };
    let origin = origin_of(base);
    let on_origin = |url: &str| {
        url.strip_prefix(&origin)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    };
    if !on_origin(&oauth.authorize) || !on_origin(&oauth.token) {
        return Err(REJECTED.into());
    }
    Ok(oauth)
}

/// A PKCE verifier (RFC 7636) and its S256 challenge.
#[derive(Debug, Clone, PartialEq)]
struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

fn pkce(verifier: &str) -> Pkce {
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    Pkce {
        verifier: verifier.to_owned(),
        challenge,
    }
}

fn random_text(bytes: usize) -> Result<String, String> {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).map_err(|e| e.to_string())?;
    Ok(URL_SAFE_NO_PAD.encode(buf))
}

/// A fresh verifier: 64 random bytes, 86 characters.
fn random_pkce() -> Result<Pkce, String> {
    Ok(pkce(&random_text(64)?))
}

/// Percent-encodes everything outside the RFC 3986 unreserved set.
fn enc(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Decodes `%XX` escapes in a query value. A malformed escape is kept as written.
fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let escape = (bytes[i] == b'%' && i + 2 < bytes.len())
            .then(|| std::str::from_utf8(&bytes[i + 1..i + 3]).ok())
            .flatten()
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        if let Some(b) = escape {
            out.push(b);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The page the browser opens: the service's authorize endpoint with PKCE and the loopback
/// redirect.
fn authorize_url(oauth: &Oauth, port: u16, state: &str, challenge: &str) -> String {
    let redirect = format!("http://127.0.0.1:{port}/callback");
    let query = [
        ("response_type", "code"),
        ("client_id", CLIENT_ID),
        ("redirect_uri", redirect.as_str()),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
        ("state", state),
        ("scope", "minecraft"),
    ];
    let pairs: Vec<String> = query
        .iter()
        .map(|(k, v)| format!("{k}={}", enc(v)))
        .collect();
    format!("{}?{}", oauth.authorize, pairs.join("&"))
}

/// The player's message for an OAuth error code (`docs/auth-providers.md`). The service's own
/// text is never shown.
fn error_message(code: &str) -> &'static str {
    match code {
        "access_denied" => DECLINED,
        "invalid_grant" => EXPIRED,
        "server_error" | "temporarily_unavailable" => UNAVAILABLE,
        _ => REJECTED,
    }
}

#[derive(Debug, PartialEq)]
pub enum Callback {
    Code(String),
    Refused(String),
    /// A callback whose state is not the one this launcher sent. It is not this sign-in's
    /// redirect, so the wait goes on.
    WrongState,
}

/// Reads the request line of a request to the loopback listener. `None` for any path other than
/// `/callback`. A state other than the one the launcher sent is `WrongState`, and no code is used.
fn read_callback(request_line: &str, state: &str) -> Option<Callback> {
    let target = request_line.split_whitespace().nth(1)?;
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if path != "/callback" {
        return None;
    }
    let (mut code, mut got_state, mut error) = (None, None, None);
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match key {
            "code" => code = Some(decode(value)),
            "state" => got_state = Some(decode(value)),
            "error" => error = Some(decode(value)),
            _ => {}
        }
    }
    if got_state.as_deref() != Some(state) {
        return Some(Callback::WrongState);
    }
    if let Some(error) = error {
        return Some(Callback::Refused(error_message(&error).into()));
    }
    Some(match code {
        Some(code) if !code.is_empty() => Callback::Code(code),
        _ => Callback::Refused(REJECTED.into()),
    })
}

/// Answers one connection on the loopback listener. `None` when the wait should go on: any path
/// other than the callback, or a callback for another state.
fn answer(stream: TcpStream, state: &str) -> Option<Result<String, String>> {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let Ok(mut writer) = stream.try_clone() else {
        return None;
    };
    let mut line = String::new();
    let capped = stream.take(MAX_REQUEST_LINE);
    if BufReader::new(capped).read_line(&mut line).is_err() {
        return None;
    }
    let outcome = read_callback(&line, state);
    let (status, body) = match &outcome {
        Some(Callback::Code(_) | Callback::Refused(_)) => (
            "200 OK",
            crate::i18n::tr("You can close this window and return to Horizon."),
        ),
        Some(Callback::WrongState) => ("400 Bad Request", ""),
        None => ("404 Not Found", ""),
    };
    let reply = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = writer.write_all(reply.as_bytes());
    match outcome? {
        Callback::Code(code) => Some(Ok(code)),
        Callback::Refused(why) => Some(Err(why)),
        Callback::WrongState => None,
    }
}

/// Waits for the browser's redirect: the code, or the player's refusal. Each connection is read on
/// its own thread, so a stalled one cannot hold the wait past the deadline or the cancel.
fn wait_for_callback(
    listener: &TcpListener,
    state: &str,
    wait: Duration,
    cancelled: &dyn Fn() -> bool,
) -> Result<String, String> {
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let deadline = Instant::now() + wait;
    let (tx, rx) = mpsc::channel();
    loop {
        if cancelled() {
            return Err("Sign-in cancelled.".into());
        }
        if Instant::now() >= deadline {
            return Err("The sign-in timed out. Start again.".into());
        }
        while let Ok(outcome) = rx.try_recv() {
            if let Some(result) = outcome {
                return result;
            }
        }
        match listener.accept() {
            Ok((stream, _)) => {
                let (tx, state) = (tx.clone(), state.to_owned());
                std::thread::spawn(move || {
                    let _ = tx.send(answer(stream, &state));
                });
            }
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// The token endpoint's answer, as the account and its secrets. A custom account has no OAuth
/// refresh token: its access token is the only secret, and renewal uses the Yggdrasil `refresh`.
fn token_response(status: u16, v: &Value, base: &str) -> Result<(Account, Secrets), String> {
    if status != 200 {
        return Err(match (v.get("error").and_then(Value::as_str), status) {
            (Some(code), _) => error_message(code).into(),
            (None, s) if s >= 500 => UNAVAILABLE.into(),
            _ => REJECTED.into(),
        });
    }
    let (Some(access), Some(profile)) = (str_field(v, "access_token"), v.get("selectedProfile"))
    else {
        return Err(REJECTED.into());
    };
    let (Some(id), Some(name)) = (str_field(profile, "id"), str_field(profile, "name")) else {
        return Err(REJECTED.into());
    };
    let expires_in = v
        .get("expires_in")
        .and_then(Value::as_u64)
        .unwrap_or(TOKEN_LIFETIME);
    let account = Account {
        uuid: id.replace('-', "").to_lowercase(),
        name,
        skin: None,
        cape: None,
        provider: Provider::HorizonAccount,
        auth_base_url: Some(base.to_owned()),
    };
    let secrets = Secrets {
        refresh_token: String::new(),
        sign_in_required: false,
        minecraft_token: access,
        minecraft_expires_at: now() + expires_in,
        xuid: None,
        owns: true,
    };
    Ok((account, secrets))
}

/// Checks a custom account's token the way `account::check` checks a Mojang one: renewed when
/// due (or `force`), through the service at the account's address, which must be https.
pub(super) fn check(account: &Account, secrets: Secrets, force: bool) -> Check {
    let base = account.auth_base_url.as_deref().unwrap_or_default();
    match refresh_url(base) {
        Ok(url) => renew(&url, account, secrets, force),
        Err(e) => Check::NoAnswer(e, secrets),
    }
}

/// The service's `authserver/<name>` under `base`, for an address `horizon_account_host` accepts.
fn authserver_url(base: &str, name: &str) -> Result<String, String> {
    crate::account::horizon_account_host(base).map_err(str::to_owned)?;
    Ok(format!("{}/authserver/{name}", base.trim_end_matches('/')))
}

fn refresh_url(base: &str) -> Result<String, String> {
    authserver_url(base, "refresh")
}

/// Renews the token at `url` when due (less than an hour left) or when `force` is set. A token
/// the service refuses needs a new browser sign-in; an outage keeps the token for a retry.
pub(super) fn renew(url: &str, account: &Account, mut secrets: Secrets, force: bool) -> Check {
    if secrets.sign_in_required {
        return Check::NoAnswer(HORIZON_ACCOUNT_SIGN_IN_AGAIN.into(), secrets);
    }
    if !force && secrets.minecraft_expires_at > now() + RENEW_BEFORE {
        return Check::Owns(account.clone(), secrets);
    }
    match refresh(url, &secrets.minecraft_token, &account.uuid) {
        Ok(access) => Check::Owns(
            account.clone(),
            Secrets {
                minecraft_token: access,
                minecraft_expires_at: now() + TOKEN_LIFETIME,
                ..secrets
            },
        ),
        Err(e) => {
            secrets.sign_in_required = e == HORIZON_ACCOUNT_SIGN_IN_AGAIN;
            Check::NoAnswer(e, secrets)
        }
    }
}

/// Yggdrasil's refresh (D25): the new access token for the profile `uuid`. The service answers
/// `ForbiddenOperationException` for a token it no longer knows.
fn refresh(url: &str, access: &str, uuid: &str) -> Result<String, String> {
    let (status, v) = send(
        request_to("POST", url),
        Some(Body::Json(json!({ "accessToken": access }))),
        "the sign-in service",
    )?;
    let token = str_field(&v, "accessToken");
    let profile = v.get("selectedProfile").and_then(|p| str_field(p, "id"));
    let forbidden = str_field(&v, "error").as_deref() == Some("ForbiddenOperationException");
    match (status, token, profile) {
        (200, Some(token), Some(id)) if id.replace('-', "").eq_ignore_ascii_case(uuid) => Ok(token),
        (200, Some(_), Some(_)) => Err(HORIZON_ACCOUNT_SIGN_IN_AGAIN.into()),
        (403, _, _) if forbidden => Err(HORIZON_ACCOUNT_SIGN_IN_AGAIN.into()),
        _ => Err(UNAVAILABLE.into()),
    }
}

/// Revokes every token of the account of `access` (`authserver/signout`, D45). Only a 204
/// confirms it: any other answer leaves the launcher unable to say what the service revoked.
pub(super) fn revoke(url: &str, access: &str) -> bool {
    matches!(
        send(
            request_to("POST", url),
            Some(Body::Json(json!({ "accessToken": access }))),
            "the sign-in service",
        ),
        Ok((204, _))
    )
}

/// Revokes a custom account's tokens on its service. False, with nothing sent, when the
/// account's address is not https.
pub(super) fn revoke_account(account: &Account, access: &str) -> bool {
    let Some(base) = account.auth_base_url.as_deref() else {
        return false;
    };
    authserver_url(base, "signout").is_ok_and(|url| revoke(&url, access))
}

/// The code exchange. The service refuses a request without its own `Origin`.
fn exchange(
    token_url: &str,
    origin: &str,
    base: &str,
    code: &str,
    verifier: &str,
    redirect: &str,
) -> Result<(Account, Secrets), String> {
    let request = request_to("POST", token_url).set("Origin", origin);
    let (status, v) = send(
        request,
        Some(Body::Form(vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("code_verifier", verifier),
            ("redirect_uri", redirect),
            ("client_id", CLIENT_ID),
        ])),
        "the sign-in service",
    )?;
    token_response(status, &v, base)
}

/// The origin (`https://host[:port]`) of a base URL: what the `Origin` header carries.
fn origin_of(base: &str) -> String {
    let scheme_end = base.find("://").map_or(0, |i| i + 3);
    let authority_end = base[scheme_end..]
        .find('/')
        .map_or(base.len(), |i| scheme_end + i);
    base[..authority_end].to_owned()
}

/// The whole custom sign-in: discover the endpoints, listen on the loopback address, hand the
/// authorize URL to `announce` for the browser, then exchange the code. `cancelled` ends the wait.
/// `base` must pass the same HTTPS check as the saved address.
pub fn sign_in(
    base: &str,
    cancelled: &dyn Fn() -> bool,
    announce: &dyn Fn(&str),
) -> Result<(Account, Secrets), String> {
    let base = base.trim_end_matches('/');
    crate::account::horizon_account_host(base).map_err(str::to_owned)?;
    let oauth = discover(base)?;
    let state = random_text(16)?;
    let pkce = random_pkce()?;
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|_| "Could not start the sign-in listener.".to_owned())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    announce(&authorize_url(&oauth, port, &state, &pkce.challenge));
    let code = wait_for_callback(&listener, &state, CALLBACK_WAIT, cancelled)?;
    let redirect = format!("http://127.0.0.1:{port}/callback");
    exchange(
        &oauth.token,
        &origin_of(base),
        base,
        &code,
        &pkce.verifier,
        &redirect,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    #[test]
    fn pkce_challenge_matches_the_rfc_7636_example() {
        let p = pkce("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        assert_eq!(p.challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn the_refresh_address_is_the_service_base_with_its_path() {
        assert_eq!(
            refresh_url("https://auth.example.org/").as_deref(),
            Ok("https://auth.example.org/authserver/refresh")
        );
        assert_eq!(
            refresh_url("https://auth.example.org/base/").as_deref(),
            Ok("https://auth.example.org/base/authserver/refresh")
        );
    }

    #[test]
    fn a_random_verifier_is_within_rfc_7636_length_and_differs_each_time() {
        let a = random_pkce().unwrap();
        let b = random_pkce().unwrap();
        assert!((43..=128).contains(&a.verifier.len()));
        assert_ne!(a.verifier, b.verifier);
    }

    #[test]
    fn the_authorize_url_carries_pkce_s256_state_and_the_loopback_redirect() {
        let oauth = Oauth {
            authorize: "https://auth.example.org/oauth/authorize".into(),
            token: "https://auth.example.org/oauth/token".into(),
        };
        let url = authorize_url(&oauth, 4321, "STATE", "CHAL");
        assert!(url.starts_with("https://auth.example.org/oauth/authorize?"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=horizon-launcher"));
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A4321%2Fcallback"));
        assert!(url.contains("code_challenge=CHAL"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("state=STATE"));
        assert!(url.contains("scope=minecraft"));
    }

    #[test]
    fn discovery_reads_the_oauth_endpoints_and_refuses_a_newer_service() {
        let endpoints = json!({"oauth": {"endpoints": {
            "authorize": {"uri": "https://a.example/oauth/authorize"},
            "token": {"uri": "https://a.example/oauth/token"}
        }}});
        let doc = json!({"meta": {"horizonAuth": 1}, "discovery": endpoints});
        let o = oauth_endpoints(&doc).unwrap();
        assert_eq!(o.authorize, "https://a.example/oauth/authorize");
        assert_eq!(o.token, "https://a.example/oauth/token");
        let no_meta = json!({"discovery": endpoints});
        assert!(oauth_endpoints(&no_meta).is_ok());
        let newer = json!({"meta": {"horizonAuth": 2}, "discovery": endpoints});
        assert_eq!(oauth_endpoints(&newer).err().as_deref(), Some(TOO_NEW));
    }

    #[test]
    fn a_horizon_auth_that_is_not_a_whole_number_is_refused_as_too_new() {
        let endpoints = json!({"oauth": {"endpoints": {
            "authorize": {"uri": "https://a.example/oauth/authorize"},
            "token": {"uri": "https://a.example/oauth/token"}
        }}});
        for odd in [json!("2"), json!(2.0), json!(-1)] {
            let doc = json!({"meta": {"horizonAuth": odd}, "discovery": endpoints});
            assert_eq!(oauth_endpoints(&doc).err().as_deref(), Some(TOO_NEW));
        }
    }

    #[test]
    fn a_callback_with_the_expected_state_gives_its_code() {
        assert_eq!(
            read_callback("GET /callback?code=abc&state=S1 HTTP/1.1", "S1"),
            Some(Callback::Code("abc".into()))
        );
    }

    #[test]
    fn a_percent_encoded_code_is_decoded_before_the_exchange() {
        assert_eq!(
            read_callback("GET /callback?code=a%2Fb%3D&state=S1 HTTP/1.1", "S1"),
            Some(Callback::Code("a/b=".into()))
        );
    }

    #[test]
    fn a_callback_with_another_state_is_not_used_and_does_not_end_the_wait() {
        assert_eq!(
            read_callback("GET /callback?code=abc&state=OTHER HTTP/1.1", "S1"),
            Some(Callback::WrongState)
        );
    }

    #[test]
    fn a_decline_in_the_browser_is_refused_with_its_message() {
        assert_eq!(
            read_callback("GET /callback?error=access_denied&state=S1 HTTP/1.1", "S1"),
            Some(Callback::Refused(
                "Sign-in was declined in the browser.".into()
            ))
        );
    }

    #[test]
    fn other_paths_are_not_the_callback() {
        assert_eq!(read_callback("GET /favicon.ico HTTP/1.1", "S1"), None);
    }

    #[test]
    fn a_token_response_becomes_a_custom_account_with_a_dashless_uuid() {
        let body = json!({
            "access_token": "tok",
            "token_type": "Bearer",
            "expires_in": 86400,
            "selectedProfile": {"id": "0B6F0A4E-2C9D-4F7A-8E1B-3C5D7F9A2B4C", "name": "Steve"}
        });
        let (account, secrets) = token_response(200, &body, "https://auth.example.org").unwrap();
        assert_eq!(account.uuid, "0b6f0a4e2c9d4f7a8e1b3c5d7f9a2b4c");
        assert_eq!(account.name, "Steve");
        assert_eq!(account.provider, Provider::HorizonAccount);
        assert_eq!(
            account.auth_base_url.as_deref(),
            Some("https://auth.example.org")
        );
        assert_eq!(secrets.minecraft_token, "tok");
    }

    #[test]
    fn each_token_error_shows_its_agreed_message() {
        let cases = [
            ("access_denied", "Sign-in was declined in the browser."),
            ("invalid_grant", "The sign-in expired. Start again."),
            (
                "invalid_request",
                "The sign-in service rejected the request.",
            ),
            (
                "temporarily_unavailable",
                "The sign-in service is unavailable. Try again later.",
            ),
        ];
        for (code, message) in cases {
            let err = token_response(400, &json!({"error": code}), "https://a.example").err();
            assert_eq!(err.as_deref(), Some(message), "{code}");
        }
    }

    #[test]
    fn the_services_own_error_text_never_reaches_the_player() {
        let body = json!({"error": "weird_code", "error_description": "internal stack detail"});
        let err = token_response(400, &body, "https://a.example")
            .err()
            .unwrap();
        assert!(
            !err.contains("weird_code") && !err.contains("internal"),
            "{err}"
        );
    }

    /// A one-shot HTTP server: records the request headers (lowercased) and answers `status` with
    /// `body`. Returns its port and the recorded headers.
    fn serve_once(status: u16, body: serde_json::Value) -> (u16, Arc<Mutex<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(String::new()));
        let record = seen.clone();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let mut length = 0usize;
            let mut headers = String::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                let lower = line.to_ascii_lowercase();
                if let Some(v) = lower.strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap_or(0);
                }
                headers.push_str(&lower);
            }
            let mut sink = vec![0u8; length];
            reader.read_exact(&mut sink).unwrap();
            *record.lock().unwrap() = headers;
            let text = body.to_string();
            let reply = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                text.len()
            );
            reader.get_mut().write_all(reply.as_bytes()).unwrap();
        });
        (port, seen)
    }

    #[test]
    fn the_token_request_sends_the_service_origin() {
        let body = json!({
            "access_token": "tok",
            "expires_in": 86400,
            "selectedProfile": {"id": "0b6f0a4e2c9d4f7a8e1b3c5d7f9a2b4c", "name": "Steve"}
        });
        let (port, seen) = serve_once(200, body);
        let token_url = format!("http://127.0.0.1:{port}/oauth/token");
        exchange(
            &token_url,
            "https://auth.example.org",
            "https://auth.example.org",
            "CODE",
            "VERIFIER",
            "http://127.0.0.1:9/callback",
        )
        .unwrap();
        assert!(
            seen.lock()
                .unwrap()
                .contains("origin: https://auth.example.org"),
            "{}",
            seen.lock().unwrap()
        );
    }

    #[test]
    fn the_origin_of_a_base_drops_its_path() {
        assert_eq!(
            origin_of("https://auth.example.org/base/"),
            "https://auth.example.org"
        );
        assert_eq!(
            origin_of("https://auth.example.org:8443"),
            "https://auth.example.org:8443"
        );
    }

    #[test]
    fn a_callback_that_never_comes_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let result = wait_for_callback(&listener, "S1", Duration::from_millis(200), &|| false);
        assert!(result.is_err());
    }

    #[test]
    fn a_stalled_connection_does_not_hold_the_wait_past_its_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        // A client that connects and sends nothing: its read must not block the wait.
        let _stalled = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let started = Instant::now();
        let result = wait_for_callback(&listener, "S1", Duration::from_millis(300), &|| false);
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}
