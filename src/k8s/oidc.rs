//! Refresh kubeconfig `auth-provider: oidc` tokens and save them back.
//!
//! kube-rs refreshes an expired id-token in memory only. Identity providers
//! such as Dex rotate the refresh token on every use, so the copy left in the
//! kubeconfig is spent, and the next kubectl that refreshes with it is
//! refused ("Refresh token is invalid or has already been claimed"). The
//! reverse happens too: kubectl saves the token it rotated, and a client
//! that only remembers its own keeps sending the spent one. Like client-go,
//! re-read the kubeconfig before refreshing and save the new tokens straight
//! after, so every client sharing the user entry holds the same refresh
//! token.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc, LazyLock, Mutex, OnceLock, PoisonError, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use anyhow::{Context as _, Result, anyhow, bail};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use futures_util::future::BoxFuture;
use http::{
    HeaderValue, Request, Response, StatusCode,
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
};
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::body::Bytes;
use k8s_openapi::jiff::{SignedDuration, Timestamp};
use kube::{Config, client::Body};
use serde_yaml::{Mapping, Value};
use tower::{BoxError, Layer, Service};

/// Refresh this long before the id-token expires, as client-go does.
const REFRESH_BEFORE: SignedDuration = SignedDuration::from_secs(10);
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long to wait for another writer's `<kubeconfig>.lock`.
#[cfg(not(test))]
const LOCK_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(test)]
const LOCK_TIMEOUT: Duration = Duration::from_millis(200);
/// How often to retry saving tokens the kubeconfig refused.
#[cfg(not(test))]
const SAVE_RETRY: Duration = Duration::from_secs(30);
#[cfg(test)]
const SAVE_RETRY: Duration = Duration::ZERO;
const LOCK_RETRY: Duration = Duration::from_millis(50);
const MAX_RESPONSE_BYTES: usize = 1 << 20;
const MAX_REASON_CHARS: usize = 200;

/// One `users` entry in one kubeconfig file.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    path: PathBuf,
    user: String,
}

/// The tokens a kubeconfig entry holds.
#[derive(Clone, Default, PartialEq, Eq)]
struct Stored {
    id_token: Option<String>,
    refresh_token: Option<String>,
}

struct Grant {
    issuer: String,
    client_id: String,
    client_secret: Option<String>,
    refresh_token: String,
}

struct Issued {
    id_token: String,
    refresh_token: Option<String>,
}

enum ExchangeError {
    /// The provider refused the refresh token: spent, revoked, or expired.
    Rejected(String),
    Failed(anyhow::Error),
}

type Exchange =
    Arc<dyn Fn(Grant) -> BoxFuture<'static, Result<Issued, ExchangeError>> + Send + Sync>;

struct Tokens {
    id_token: Option<String>,
    refresh_token: String,
    /// What the kubeconfig held when last read or written. A file that
    /// differs from it was changed by someone else since.
    seen: Stored,
    /// Why the provider refused `refresh_token`. Sending it again cannot
    /// work, so this holds until the refresh token changes.
    rejected: Option<String>,
    /// Tokens a refresh issued that are not in the kubeconfig yet. Until
    /// they are, kubectl only has the spent refresh token.
    unsaved: Option<Unsaved>,
}

struct Unsaved {
    /// The refresh token the kubeconfig held when it was sent. An entry
    /// that holds another one was changed by a newer login since.
    replaces: String,
    tokens: Stored,
    retry_at: std::time::Instant,
}

/// What the kubeconfig says about a login apart from its tokens. Read again
/// whenever a client is built for the login.
struct Login {
    client_secret: Option<String>,
    entries: Arc<[Entry]>,
}

/// The refresh state for one OIDC login, shared by every client built for
/// the same kubeconfig entries so they never race each other to the
/// provider with one refresh token.
struct Session {
    issuer: String,
    client_id: String,
    login: Mutex<Login>,
    exchange: Exchange,
    /// The API server refused the id-token: consult the kubeconfig again.
    stale: AtomicBool,
    tokens: tokio::sync::Mutex<Tokens>,
}

static SESSIONS: Mutex<Vec<Weak<Session>>> = Mutex::new(Vec::new());

/// Authenticates requests with the session's id-token.
#[derive(Clone)]
pub(crate) struct OidcLayer {
    session: Arc<Session>,
}

/// The refresh layer for `config`'s `oidc` auth-provider, or `None` to leave
/// authentication to kube-rs: another auth mode, a provider without a
/// refresh token, or one no kubeconfig file holds, so there is nowhere to
/// save a rotated token.
pub(crate) fn layer(config: &Config) -> Option<OidcLayer> {
    layer_in(
        config,
        &kubeconfig_paths(),
        Arc::new(|grant| Box::pin(http_exchange(grant))),
    )
}

fn layer_in(config: &Config, paths: &[PathBuf], exchange: Exchange) -> Option<OidcLayer> {
    let auth = &config.auth_info;
    // kube-rs prefers these over an auth-provider.
    if auth.token.is_some() || auth.token_file.is_some() || auth.username.is_some() {
        return None;
    }
    let provider = auth
        .auth_provider
        .as_ref()
        .filter(|provider| provider.name == "oidc")?;
    let field = |key: &str| {
        provider
            .config
            .get(key)
            .filter(|value| !value.is_empty())
            .cloned()
    };
    let issuer = field("idp-issuer-url")?;
    let client_id = field("client-id")?;
    let refresh_token = field("refresh-token")?;
    let entries = locate(paths, &issuer, &client_id, &refresh_token);
    if entries.is_empty() {
        return None;
    }
    let id_token = field("id-token");
    let session = Session {
        issuer,
        client_id,
        login: Mutex::new(Login {
            client_secret: field("client-secret"),
            entries: entries.into(),
        }),
        exchange,
        stale: AtomicBool::new(false),
        tokens: tokio::sync::Mutex::new(Tokens {
            seen: Stored {
                id_token: id_token.clone(),
                refresh_token: Some(refresh_token.clone()),
            },
            id_token,
            refresh_token,
            rejected: None,
            unsaved: None,
        }),
    };
    Some(OidcLayer {
        session: shared(session),
    })
}

/// A live session for the same login, or `session` registered as one.
fn shared(session: Session) -> Arc<Session> {
    let mut sessions = SESSIONS.lock().unwrap_or_else(PoisonError::into_inner);
    sessions.retain(|weak| weak.strong_count() > 0);
    let entries = session.entries();
    let existing = sessions.iter().filter_map(Weak::upgrade).find(|live| {
        live.issuer == session.issuer
            && live.client_id == session.client_id
            && live.entries().iter().any(|entry| entries.contains(entry))
    });
    crate::log_debug!(
        "cluster.oidc.session",
        user = session.user(),
        reused = existing.is_some()
    );
    if let Some(existing) = existing {
        // The new client was built from the file, which may be newer.
        existing.update(
            session
                .login
                .into_inner()
                .unwrap_or_else(PoisonError::into_inner),
        );
        existing.stale.store(true, Ordering::Release);
        return existing;
    }
    let session = Arc::new(session);
    sessions.push(Arc::downgrade(&session));
    session
}

/// The files kube-rs merges, in order.
fn kubeconfig_paths() -> Vec<PathBuf> {
    match std::env::var_os("KUBECONFIG").filter(|value| !value.is_empty()) {
        Some(value) => std::env::split_paths(&value)
            .filter(|path| !path.as_os_str().is_empty())
            .collect(),
        None => crate::config::home_dir()
            .map(|home| PathBuf::from(home).join(".kube").join("config"))
            .into_iter()
            .collect(),
    }
}

/// The kubeconfig entries that hold this login. Copies of one user under
/// several names share the refresh token, so each of them must be updated.
fn locate(paths: &[PathBuf], issuer: &str, client_id: &str, refresh_token: &str) -> Vec<Entry> {
    let mut entries = Vec::new();
    for path in paths {
        let Some(document) = read_document(path) else {
            continue;
        };
        for (user, config) in oidc_users(&document) {
            if same_login(config, issuer, client_id)
                && text(config, "refresh-token") == Some(refresh_token)
            {
                entries.push(Entry {
                    path: path.clone(),
                    user: user.to_owned(),
                });
            }
        }
    }
    entries
}

fn read_document(path: &Path) -> Option<Value> {
    let contents = std::fs::read_to_string(path).ok()?;
    serde_yaml::from_str(&contents).ok()
}

/// `(user name, auth-provider config)` for each `oidc` user in `document`.
fn oidc_users(document: &Value) -> impl Iterator<Item = (&str, &Mapping)> {
    document
        .get("users")
        .and_then(Value::as_sequence)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let name = entry.get("name")?.as_str()?;
            let provider = entry.get("user")?.get("auth-provider")?;
            if provider.get("name")?.as_str()? != "oidc" {
                return None;
            }
            Some((name, provider.get("config")?.as_mapping()?))
        })
}

fn oidc_config_mut<'a>(document: &'a mut Value, user: &str) -> Option<&'a mut Mapping> {
    document
        .get_mut("users")?
        .as_sequence_mut()?
        .iter_mut()
        .find(|entry| entry.get("name").and_then(Value::as_str) == Some(user))?
        .get_mut("user")?
        .get_mut("auth-provider")?
        .get_mut("config")?
        .as_mapping_mut()
}

fn text<'a>(config: &'a Mapping, key: &str) -> Option<&'a str> {
    config
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

/// Whether a user's provider config is still this login: the same issuer
/// and client. A user entry renamed or repurposed since must not have its
/// tokens read, sent to this issuer, or overwritten.
fn same_login(config: &Mapping, issuer: &str, client_id: &str) -> bool {
    text(config, "idp-issuer-url") == Some(issuer) && text(config, "client-id") == Some(client_id)
}

/// The tokens the first entry still holding this login has.
fn read_stored(entries: &[Entry], issuer: &str, client_id: &str) -> Option<Stored> {
    entries.iter().find_map(|entry| {
        let document = read_document(&entry.path)?;
        let (_, config) = oidc_users(&document)
            .find(|(user, config)| *user == entry.user && same_login(config, issuer, client_id))?;
        Some(Stored {
            id_token: text(config, "id-token").map(str::to_owned),
            refresh_token: text(config, "refresh-token").map(str::to_owned),
        })
    })
}

/// Write `stored` into every entry that still holds the refresh token
/// `replaces`, holding the file's lock as client-go does while it saves a
/// refreshed token. False when an entry held another refresh token: a newer
/// login saved it, and it is left alone. The file is replaced in one step by
/// a copy with its owner, group and mode, or written in place as client-go
/// does when such a copy would not keep all of its protection.
fn persist(
    entries: &[Entry],
    (issuer, client_id): (&str, &str),
    replaces: &str,
    stored: &Stored,
) -> Result<bool> {
    let mut paths: Vec<&Path> = entries.iter().map(|entry| entry.path.as_path()).collect();
    paths.dedup();
    let mut all = true;
    for path in paths {
        let _locks = lock_kubeconfig(path)?;
        let contents =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut document: Value = serde_yaml::from_str(&contents)
            .with_context(|| format!("parsing {}", path.display()))?;
        let mut changed = false;
        for entry in entries.iter().filter(|entry| entry.path == path) {
            let Some(config) = oidc_config_mut(&mut document, &entry.user)
                .filter(|config| same_login(config, issuer, client_id))
            else {
                continue;
            };
            if text(config, "refresh-token") != Some(replaces) {
                all = false;
                continue;
            }
            for (key, value) in [
                ("id-token", &stored.id_token),
                ("refresh-token", &stored.refresh_token),
            ] {
                if let Some(value) = value {
                    config.insert(key.into(), value.as_str().into());
                }
            }
            changed = true;
        }
        if changed {
            let contents = serde_yaml::to_string(&document)?;
            match crate::atomicfile::replace(path, &contents) {
                Ok(()) => {}
                // A new copy could not keep the file's owner, ACL, or
                // security label: write in place, as client-go does.
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::Unsupported
                    ) =>
                {
                    std::fs::write(path, &contents)
                        .with_context(|| format!("writing {}", path.display()))?;
                }
                Err(error) => {
                    return Err(error).with_context(|| format!("writing {}", path.display()));
                }
            }
        }
    }
    Ok(all)
}

/// The locks a writer of `path` takes: client-go locks `<path>.lock` for the
/// path it was given, so a symlinked kubeconfig also needs its target's.
fn lock_kubeconfig(path: &Path) -> Result<Vec<FileLock>> {
    let mut locks = vec![FileLock::acquire(path)?];
    if std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink()) {
        let target =
            std::fs::canonicalize(path).with_context(|| format!("resolving {}", path.display()))?;
        locks.push(FileLock::acquire(&target)?);
    }
    Ok(locks)
}

/// The lock file client-go creates beside a kubeconfig it modifies.
struct FileLock(PathBuf);

impl FileLock {
    fn acquire(path: &Path) -> Result<Self> {
        let mut name = path.as_os_str().to_owned();
        name.push(".lock");
        let lock = PathBuf::from(name);
        let deadline = std::time::Instant::now() + LOCK_TIMEOUT;
        loop {
            match std::fs::File::options()
                .write(true)
                .create_new(true)
                .open(&lock)
            {
                Ok(_) => return Ok(Self(lock)),
                Err(error)
                    if error.kind() == std::io::ErrorKind::AlreadyExists
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(LOCK_RETRY);
                }
                Err(error) => {
                    return Err(error).with_context(|| format!("locking {}", lock.display()));
                }
            }
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Seconds-since-epoch `exp` claim of a JWT, without verifying it: the API
/// server does that. Only decides when to refresh.
fn expiry(token: &str) -> Option<Timestamp> {
    let payload = token.split('.').nth(1)?;
    let payload = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    Timestamp::from_second(claims.get("exp")?.as_i64()?).ok()
}

/// A token without a readable expiry is used until the server refuses it.
fn usable(id_token: Option<&str>, now: Timestamp) -> bool {
    id_token.is_some_and(|token| expiry(token).is_none_or(|exp| now + REFRESH_BEFORE < exp))
}

impl Session {
    async fn bearer(&self) -> Result<String, BoxError> {
        let mut tokens = self.tokens.lock().await;
        if tokens
            .unsaved
            .as_ref()
            .is_some_and(|unsaved| std::time::Instant::now() >= unsaved.retry_at)
        {
            self.save(&mut tokens).await;
        }
        let stale = self.stale.swap(false, Ordering::AcqRel);
        if stale || !usable(tokens.id_token.as_deref(), Timestamp::now()) {
            self.adopt_stored(&mut tokens).await;
        }
        if !usable(tokens.id_token.as_deref(), Timestamp::now()) {
            self.refresh(&mut tokens).await?;
        }
        tokens
            .id_token
            .clone()
            .ok_or_else(|| "the OIDC provider issued no id-token".into())
    }

    /// Take the kubeconfig's tokens when another client changed them since
    /// this session last read or wrote the file.
    async fn adopt_stored(&self, tokens: &mut Tokens) {
        let entries = self.entries();
        let (issuer, client_id) = (self.issuer.clone(), self.client_id.clone());
        let Ok(Some(stored)) =
            tokio::task::spawn_blocking(move || read_stored(&entries, &issuer, &client_id)).await
        else {
            return;
        };
        if stored == tokens.seen {
            return;
        }
        if let Some(refresh_token) = &stored.refresh_token
            && *refresh_token != tokens.refresh_token
        {
            tokens.refresh_token = refresh_token.clone();
            tokens.rejected = None;
        }
        tokens.id_token = stored.id_token.clone();
        tokens.seen = stored;
        crate::log_info!(
            "cluster.oidc.reloaded",
            user = self.user(),
            refresh = fingerprint(&tokens.refresh_token)
        );
    }

    async fn refresh(&self, tokens: &mut Tokens) -> Result<(), BoxError> {
        if let Some(reason) = &tokens.rejected {
            return Err(rejected_message(reason).into());
        }
        let sent = fingerprint(&tokens.refresh_token);
        crate::log_debug!(
            "cluster.oidc.refreshing",
            user = self.user(),
            refresh = sent
        );
        let grant = Grant {
            issuer: self.issuer.clone(),
            client_id: self.client_id.clone(),
            client_secret: self.login().client_secret.clone(),
            refresh_token: tokens.refresh_token.clone(),
        };
        let issued = match tokio::time::timeout(EXCHANGE_TIMEOUT, (self.exchange)(grant)).await {
            Ok(Ok(issued)) => issued,
            Ok(Err(ExchangeError::Rejected(reason))) => {
                crate::log_warn!(
                    "cluster.oidc.rejected",
                    user = self.user(),
                    refresh = sent,
                    reason = reason
                );
                let message = rejected_message(&reason);
                tokens.rejected = Some(reason);
                return Err(message.into());
            }
            Ok(Err(ExchangeError::Failed(error))) => {
                return Err(
                    format!("refreshing the OIDC token with {}: {error:#}", self.issuer).into(),
                );
            }
            Err(_) => {
                return Err(
                    format!("refreshing the OIDC token with {} timed out", self.issuer).into(),
                );
            }
        };
        let replaces = std::mem::take(&mut tokens.refresh_token);
        tokens.id_token = Some(issued.id_token);
        tokens.refresh_token = issued.refresh_token.unwrap_or_else(|| replaces.clone());
        tokens.rejected = None;
        crate::log_info!(
            "cluster.oidc.refreshed",
            user = self.user(),
            sent = sent,
            refresh = fingerprint(&tokens.refresh_token)
        );
        tokens.unsaved = Some(Unsaved {
            replaces,
            tokens: Stored {
                id_token: tokens.id_token.clone(),
                refresh_token: Some(tokens.refresh_token.clone()),
            },
            retry_at: std::time::Instant::now(),
        });
        self.save(tokens).await;
        Ok(())
    }

    /// Write the tokens the last refresh issued into the kubeconfig. Kept
    /// for a later request when the file cannot be written; given up when a
    /// newer login replaced the refresh token there, which the next request
    /// then adopts.
    async fn save(&self, tokens: &mut Tokens) {
        let Some(mut unsaved) = tokens.unsaved.take() else {
            return;
        };
        let entries = self.entries();
        let (issuer, client_id) = (self.issuer.clone(), self.client_id.clone());
        let (replaces, stored) = (unsaved.replaces.clone(), unsaved.tokens.clone());
        let saved = tokio::task::spawn_blocking(move || {
            persist(&entries, (&issuer, &client_id), &replaces, &stored)
        })
        .await
        .map_err(anyhow::Error::from)
        .and_then(|saved| saved);
        match saved {
            Ok(true) => tokens.seen = unsaved.tokens,
            Ok(false) => {
                crate::log_info!("cluster.oidc.superseded", user = self.user());
                self.stale.store(true, Ordering::Release);
            }
            Err(error) => {
                crate::log_warn!(
                    "cluster.oidc.save_failed",
                    user = self.user(),
                    refresh = fingerprint(&tokens.refresh_token),
                    error = format!("{error:#}")
                );
                unsaved.retry_at = std::time::Instant::now() + SAVE_RETRY;
                tokens.unsaved = Some(unsaved);
            }
        }
    }

    fn login(&self) -> std::sync::MutexGuard<'_, Login> {
        self.login.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn entries(&self) -> Arc<[Entry]> {
        Arc::clone(&self.login().entries)
    }

    /// Take what a newer read of the kubeconfig says about this login: its
    /// client secret, and entries that hold it now.
    fn update(&self, newer: Login) {
        let mut login = self.login();
        login.client_secret = newer.client_secret;
        let added: Vec<Entry> = newer
            .entries
            .iter()
            .filter(|entry| !login.entries.contains(entry))
            .cloned()
            .collect();
        if !added.is_empty() {
            login.entries = login.entries.iter().cloned().chain(added).collect();
        }
    }

    /// The kubeconfig user this login belongs to, for the log.
    fn user(&self) -> String {
        self.login()
            .entries
            .first()
            .map(|entry| entry.user.clone())
            .unwrap_or_default()
    }
}

/// A short, irreversible tag for a token, so the log can show which refresh
/// token each client sent without revealing it.
fn fingerprint(token: &str) -> String {
    blake3::hash(token.as_bytes()).to_hex()[..8].to_owned()
}

fn rejected_message(reason: &str) -> String {
    let reason = if reason.is_empty() {
        String::new()
    } else {
        format!(" ({reason})")
    };
    format!(
        "the identity provider refused the OIDC refresh token{reason}; log in again, and sofka picks up the new token from the kubeconfig"
    )
}

/// Provider text shown in the TUI: one line, bounded.
fn reason_text(reason: &str) -> String {
    let line: String = reason.chars().filter(|c| !c.is_control()).collect();
    crate::text::ellipsize(&line, MAX_REASON_CHARS)
}

impl<S> Layer<S> for OidcLayer {
    type Service = OidcService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        OidcService {
            inner,
            session: self.session.clone(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct OidcService<S> {
    inner: S,
    session: Arc<Session>,
}

impl<S, B> Service<Request<Body>> for OidcService<S>
where
    S: Service<Request<Body>, Response = Response<B>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Into<BoxError>,
    B: Send + 'static,
{
    type Response = Response<B>;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Response<B>, BoxError>>;

    fn poll_ready(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), BoxError>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        // The clone may not be ready; keep the one `poll_ready` prepared.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let session = self.session.clone();
        Box::pin(async move {
            let token = session.bearer().await?;
            let mut value = HeaderValue::try_from(format!("Bearer {token}"))?;
            value.set_sensitive(true);
            request.headers_mut().insert(AUTHORIZATION, value);
            let response = inner.call(request).await.map_err(Into::into)?;
            if response.status() == StatusCode::UNAUTHORIZED {
                session.stale.store(true, Ordering::Release);
            }
            Ok(response)
        })
    }
}

type ProviderClient = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
>;

/// One client for every refresh: the system trust store is read once, and
/// connections to the provider are reused.
fn provider_client() -> Result<ProviderClient> {
    static CLIENT: OnceLock<ProviderClient> = OnceLock::new();
    if let Some(client) = CLIENT.get() {
        return Ok(client.clone());
    }
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .context("loading system trust roots")?
        .https_or_http()
        .enable_http1()
        .build();
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build(connector);
    Ok(CLIENT.get_or_init(|| client).clone())
}

/// Token endpoints found through discovery, by issuer.
static TOKEN_ENDPOINTS: LazyLock<Mutex<HashMap<String, String>>> = LazyLock::new(Mutex::default);

async fn send(
    client: &ProviderClient,
    request: Request<Full<Bytes>>,
) -> Result<(StatusCode, Bytes)> {
    let response = client.request(request).await?;
    let status = response.status();
    let body = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
        .collect()
        .await
        .map_err(|error| anyhow!("{error}"))?
        .to_bytes();
    Ok((status, body))
}

/// The issuer's token endpoint, from its OIDC discovery document.
async fn discover(client: &ProviderClient, issuer: &str) -> Result<String> {
    let discovery = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let request = Request::get(&discovery)
        .header(ACCEPT, "application/json")
        .body(Full::default())?;
    let (status, body) = send(client, request)
        .await
        .with_context(|| format!("fetching {discovery}"))?;
    if !status.is_success() {
        bail!("{discovery} returned {status}");
    }
    #[derive(serde::Deserialize)]
    struct Discovery {
        token_endpoint: String,
    }
    Ok(serde_json::from_slice::<Discovery>(&body)
        .with_context(|| format!("parsing {discovery}"))?
        .token_endpoint)
}

/// Exchange a refresh token at the issuer's token endpoint. The endpoint is
/// discovered once per issuer, and again after a failed exchange. The
/// provider is reached with system trust.
async fn http_exchange(grant: Grant) -> Result<Issued, ExchangeError> {
    let failed = ExchangeError::Failed;
    let client = provider_client().map_err(failed)?;
    let cached = TOKEN_ENDPOINTS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&grant.issuer)
        .cloned();
    let endpoint = match cached {
        Some(endpoint) => endpoint,
        None => {
            let endpoint = discover(&client, &grant.issuer).await.map_err(failed)?;
            TOKEN_ENDPOINTS
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(grant.issuer.clone(), endpoint.clone());
            endpoint
        }
    };

    // A client secret goes in a Basic header, as client-go sends it; a
    // public client names itself in the form.
    let body = {
        let mut form = form_urlencoded::Serializer::new(String::new());
        form.append_pair("grant_type", "refresh_token")
            .append_pair("refresh_token", &grant.refresh_token);
        if grant.client_secret.is_none() {
            form.append_pair("client_id", &grant.client_id);
        }
        form.finish()
    };
    let mut request = Request::post(&endpoint)
        .header(ACCEPT, "application/json")
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(secret) = &grant.client_secret {
        let encode =
            |value: &str| -> String { form_urlencoded::byte_serialize(value.as_bytes()).collect() };
        let credentials = format!("{}:{}", encode(&grant.client_id), encode(secret));
        let mut value = HeaderValue::try_from(format!("Basic {}", STANDARD.encode(credentials)))
            .map_err(|error| failed(error.into()))?;
        value.set_sensitive(true);
        request = request.header(AUTHORIZATION, value);
    }
    let request = request
        .body(Full::new(Bytes::from(body)))
        .map_err(|error| failed(error.into()))?;
    let result = send(&client, request)
        .await
        .with_context(|| format!("posting to {endpoint}"))
        .map_err(failed)
        .and_then(|(status, body)| issued(status, &body));
    if matches!(result, Err(ExchangeError::Failed(_))) {
        TOKEN_ENDPOINTS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&grant.issuer);
    }
    result
}

/// Read a token endpoint response.
fn issued(status: StatusCode, body: &[u8]) -> Result<Issued, ExchangeError> {
    #[derive(serde::Deserialize)]
    struct TokenResponse {
        id_token: Option<String>,
        refresh_token: Option<String>,
        error: Option<String>,
        error_description: Option<String>,
    }
    let response: Option<TokenResponse> = serde_json::from_slice(body).ok();
    if !status.is_success() {
        let (error, description) = response
            .map(|response| (response.error, response.error_description))
            .unwrap_or_default();
        let reason = reason_text(description.as_deref().or(error.as_deref()).unwrap_or(""));
        // Dex answers `invalid_request` for a token another client claimed.
        return Err(match (status, error.as_deref()) {
            (
                StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED,
                Some("invalid_grant" | "invalid_request"),
            ) => ExchangeError::Rejected(reason),
            _ if reason.is_empty() => {
                ExchangeError::Failed(anyhow!("token endpoint returned {status}"))
            }
            _ => ExchangeError::Failed(anyhow!("token endpoint returned {status}: {reason}")),
        });
    }
    let Some(response) = response else {
        return Err(ExchangeError::Failed(anyhow!(
            "token endpoint returned an unreadable response"
        )));
    };
    let Some(id_token) = response.id_token.filter(|token| !token.is_empty()) else {
        return Err(ExchangeError::Failed(anyhow!(
            "token endpoint returned no id_token"
        )));
    };
    Ok(Issued {
        id_token,
        refresh_token: response.refresh_token.filter(|token| !token.is_empty()),
    })
}

#[cfg(test)]
pub(crate) fn test_token(expiry: i64) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::json!({ "exp": expiry }).to_string());
    format!("{header}.{payload}.test-signature")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    const ISSUER: &str = "https://dex.example.test";
    const LATER: i64 = 4_070_908_800;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "sofka-oidc-{}-{tag}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn kubeconfig(users: &[&str], id_token: &str, refresh_token: &str) -> String {
        let mut yaml = String::from("apiVersion: v1\nkind: Config\n# kept by the user\nusers:\n");
        for user in users {
            yaml.push_str(&format!(
                "- name: {user}\n  user:\n    auth-provider:\n      name: oidc\n      config:\n        idp-issuer-url: {ISSUER}\n        client-id: kubernetes\n        client-secret: secret\n        id-token: {id_token}\n        refresh-token: {refresh_token}\n"
            ));
        }
        yaml.push_str("- name: other\n  user:\n    token: static\n");
        yaml
    }

    fn config(id_token: &str, refresh_token: &str) -> Config {
        let mut config = Config::new("https://127.0.0.1:1".parse().unwrap());
        config.auth_info.auth_provider = Some(kube::config::AuthProviderConfig {
            name: "oidc".into(),
            config: [
                ("idp-issuer-url", ISSUER),
                ("client-id", "kubernetes"),
                ("client-secret", "secret"),
                ("id-token", id_token),
                ("refresh-token", refresh_token),
            ]
            .into_iter()
            .map(|(key, value)| (key.into(), value.into()))
            .collect(),
            ..Default::default()
        });
        config
    }

    /// A provider that rotates `refresh-N` into `refresh-N+1` and refuses
    /// any refresh token it has already seen, as Dex does. `calls` records
    /// every refresh token sent to it.
    fn provider(calls: Arc<Mutex<Vec<String>>>) -> Exchange {
        Arc::new(move |grant: Grant| {
            let calls = calls.clone();
            Box::pin(async move {
                let mut calls = calls.lock().unwrap();
                let spent = calls.contains(&grant.refresh_token);
                calls.push(grant.refresh_token.clone());
                if spent {
                    return Err(ExchangeError::Rejected(
                        "Refresh token is invalid or has already been claimed by another client."
                            .into(),
                    ));
                }
                let next = grant
                    .refresh_token
                    .replace("refresh-", "")
                    .parse::<u32>()
                    .unwrap()
                    + 1;
                Ok(Issued {
                    id_token: test_token(LATER + i64::from(next)),
                    refresh_token: Some(format!("refresh-{next}")),
                })
            })
        })
    }

    fn stored(path: &Path, user: &str) -> Stored {
        read_stored(
            &[Entry {
                path: path.into(),
                user: user.into(),
            }],
            ISSUER,
            "kubernetes",
        )
        .unwrap()
    }

    async fn call(layer: &OidcLayer, status: StatusCode) -> Result<String, BoxError> {
        let seen = Arc::new(Mutex::new(String::new()));
        let header = seen.clone();
        let mut service = layer.layer(tower::service_fn(move |request: Request<Body>| {
            let header = header.clone();
            async move {
                *header.lock().unwrap() = request.headers()[AUTHORIZATION]
                    .to_str()
                    .unwrap()
                    .to_owned();
                Ok::<_, BoxError>(Response::builder().status(status).body(()).unwrap())
            }
        }));
        std::future::poll_fn(|cx| service.poll_ready(cx)).await?;
        service.call(Request::new(Body::empty())).await?;
        let header = seen.lock().unwrap().clone();
        Ok(header)
    }

    #[tokio::test]
    async fn a_refresh_saves_both_rotated_tokens_to_every_entry() {
        let scratch = Scratch::new("save");
        let path = scratch.0.join("config");
        let expired = test_token(1);
        std::fs::write(
            &path,
            kubeconfig(&["dex", "dex-copy"], &expired, "refresh-1"),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        #[cfg(unix)]
        let owner = {
            use std::os::unix::fs::MetadataExt as _;
            let meta = std::fs::metadata(&path).unwrap();
            (meta.uid(), meta.gid())
        };
        let calls = Arc::new(Mutex::new(Vec::new()));
        let layer = layer_in(
            &config(&expired, "refresh-1"),
            std::slice::from_ref(&path),
            provider(calls.clone()),
        )
        .unwrap();

        let header = call(&layer, StatusCode::OK).await.unwrap();

        let issued = test_token(LATER + 2);
        assert_eq!(header, format!("Bearer {issued}"));
        assert_eq!(*calls.lock().unwrap(), ["refresh-1"]);
        for user in ["dex", "dex-copy"] {
            let saved = stored(&path, user);
            assert_eq!(saved.id_token.as_deref(), Some(issued.as_str()));
            assert_eq!(saved.refresh_token.as_deref(), Some("refresh-2"));
        }
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("token: static"), "{contents}");
        assert!(!std::path::Path::new(&format!("{}.lock", path.display())).exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            use std::os::unix::fs::PermissionsExt as _;
            let meta = std::fs::metadata(&path).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
            assert_eq!((meta.uid(), meta.gid()), owner);
        }

        // A valid id-token is reused without asking the provider again.
        call(&layer, StatusCode::OK).await.unwrap();
        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_token_another_client_rotated_is_used_instead_of_the_spent_one() {
        let scratch = Scratch::new("adopt");
        let path = scratch.0.join("config");
        let expired = test_token(1);
        std::fs::write(&path, kubeconfig(&["dex"], &expired, "refresh-1")).unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let exchange = provider(calls.clone());
        let layer = layer_in(
            &config(&expired, "refresh-1"),
            std::slice::from_ref(&path),
            exchange.clone(),
        )
        .unwrap();

        // kubectl refreshes first and saves what it got.
        let kubectl = (exchange)(Grant {
            issuer: ISSUER.into(),
            client_id: "kubernetes".into(),
            client_secret: None,
            refresh_token: "refresh-1".into(),
        });
        let Ok(rotated) = kubectl.await else {
            panic!("kubectl refresh failed")
        };
        std::fs::write(&path, kubeconfig(&["dex"], &rotated.id_token, "refresh-2")).unwrap();

        let header = call(&layer, StatusCode::OK).await.unwrap();
        assert_eq!(header, format!("Bearer {}", rotated.id_token));
        assert_eq!(*calls.lock().unwrap(), ["refresh-1"]);

        // Once that id-token expires too, the session refreshes with the
        // token kubectl saved, not the one it started with.
        std::fs::write(&path, kubeconfig(&["dex"], &expired, "refresh-2")).unwrap();
        layer.session.stale.store(true, Ordering::Release);
        call(&layer, StatusCode::OK).await.unwrap();
        assert_eq!(*calls.lock().unwrap(), ["refresh-1", "refresh-2"]);
        assert_eq!(
            stored(&path, "dex").refresh_token.as_deref(),
            Some("refresh-3")
        );
    }

    #[tokio::test]
    async fn unauthorized_rereads_the_kubeconfig_before_the_next_request() {
        let scratch = Scratch::new("unauthorized");
        let path = scratch.0.join("config");
        let first = test_token(LATER);
        std::fs::write(&path, kubeconfig(&["dex"], &first, "refresh-1")).unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let layer = layer_in(
            &config(&first, "refresh-1"),
            std::slice::from_ref(&path),
            provider(calls.clone()),
        )
        .unwrap();
        assert_eq!(
            call(&layer, StatusCode::OK).await.unwrap(),
            format!("Bearer {first}")
        );

        // The user logged in again, and the server refuses the old id-token.
        let second = test_token(LATER + 100);
        std::fs::write(&path, kubeconfig(&["dex"], &second, "refresh-9")).unwrap();
        call(&layer, StatusCode::UNAUTHORIZED).await.unwrap();

        assert_eq!(
            call(&layer, StatusCode::OK).await.unwrap(),
            format!("Bearer {second}")
        );
        assert!(calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_refused_refresh_token_is_reported_once_and_a_new_login_recovers() {
        let scratch = Scratch::new("rejected");
        let path = scratch.0.join("config");
        let expired = test_token(1);
        std::fs::write(&path, kubeconfig(&["dex"], &expired, "refresh-1")).unwrap();
        let calls = Arc::new(Mutex::new(vec!["refresh-1".to_owned()]));
        let layer = layer_in(
            &config(&expired, "refresh-1"),
            std::slice::from_ref(&path),
            provider(calls.clone()),
        )
        .unwrap();

        for _ in 0..2 {
            let error = call(&layer, StatusCode::OK).await.unwrap_err().to_string();
            assert!(error.contains("refused the OIDC refresh token"), "{error}");
            assert!(error.contains("already been claimed"), "{error}");
            assert!(error.contains("log in again"), "{error}");
            assert!(!error.contains("refresh-1"), "{error}");
        }
        // The spent token went to the provider only once.
        assert_eq!(*calls.lock().unwrap(), ["refresh-1", "refresh-1"]);

        std::fs::write(&path, kubeconfig(&["dex"], &expired, "refresh-5")).unwrap();
        call(&layer, StatusCode::OK).await.unwrap();
        assert_eq!(calls.lock().unwrap().last().unwrap(), "refresh-5");
        assert_eq!(
            stored(&path, "dex").refresh_token.as_deref(),
            Some("refresh-6")
        );
    }

    #[tokio::test]
    async fn clients_for_the_same_login_share_one_session() {
        let scratch = Scratch::new("shared");
        let path = scratch.0.join("config");
        let expired = test_token(1);
        std::fs::write(&path, kubeconfig(&["dex"], &expired, "refresh-1")).unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let first = layer_in(
            &config(&expired, "refresh-1"),
            std::slice::from_ref(&path),
            provider(calls.clone()),
        )
        .unwrap();
        let second = layer_in(
            &config(&expired, "refresh-1"),
            std::slice::from_ref(&path),
            provider(calls.clone()),
        )
        .unwrap();
        assert!(Arc::ptr_eq(&first.session, &second.session));

        let (a, b) = tokio::join!(call(&first, StatusCode::OK), call(&second, StatusCode::OK));
        assert_eq!(a.unwrap(), b.unwrap());
        assert_eq!(*calls.lock().unwrap(), ["refresh-1"]);
    }

    #[tokio::test]
    async fn a_login_saved_during_a_refresh_is_kept_and_used_next() {
        let scratch = Scratch::new("superseded");
        let path = scratch.0.join("config");
        let expired = test_token(1);
        std::fs::write(&path, kubeconfig(&["dex"], &expired, "refresh-1")).unwrap();
        let login = test_token(LATER + 50);
        let calls = Arc::new(Mutex::new(0));
        let exchange: Exchange = {
            let (path, login, calls) = (path.clone(), login.clone(), calls.clone());
            Arc::new(move |_grant: Grant| {
                // A new login lands while the provider answers.
                std::fs::write(&path, kubeconfig(&["dex"], &login, "refresh-9")).unwrap();
                *calls.lock().unwrap() += 1;
                Box::pin(async {
                    Ok(Issued {
                        id_token: test_token(LATER + 2),
                        refresh_token: Some("refresh-2".into()),
                    })
                })
            })
        };
        let layer = layer_in(
            &config(&expired, "refresh-1"),
            std::slice::from_ref(&path),
            exchange,
        )
        .unwrap();

        let header = call(&layer, StatusCode::OK).await.unwrap();
        assert_eq!(header, format!("Bearer {}", test_token(LATER + 2)));
        assert_eq!(
            stored(&path, "dex").refresh_token.as_deref(),
            Some("refresh-9")
        );

        assert_eq!(
            call(&layer, StatusCode::OK).await.unwrap(),
            format!("Bearer {login}")
        );
        assert_eq!(*calls.lock().unwrap(), 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_symlinked_kubeconfig_waits_for_its_target_lock_and_retries_the_save() {
        let scratch = Scratch::new("symlink");
        let target = scratch.0.join("kubeconfig");
        let link = scratch.0.join("config");
        let expired = test_token(1);
        std::fs::write(&target, kubeconfig(&["dex"], &expired, "refresh-1")).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        // Another writer that names the target directly holds its lock.
        let held = scratch.0.join("kubeconfig.lock");
        std::fs::write(&held, "").unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let layer = layer_in(
            &config(&expired, "refresh-1"),
            std::slice::from_ref(&link),
            provider(calls.clone()),
        )
        .unwrap();

        let issued = format!("Bearer {}", test_token(LATER + 2));
        assert_eq!(call(&layer, StatusCode::OK).await.unwrap(), issued);
        assert_eq!(
            stored(&target, "dex").refresh_token.as_deref(),
            Some("refresh-1")
        );
        assert!(!scratch.0.join("config.lock").exists());

        std::fs::remove_file(&held).unwrap();
        assert_eq!(call(&layer, StatusCode::OK).await.unwrap(), issued);
        assert_eq!(
            stored(&target, "dex").refresh_token.as_deref(),
            Some("refresh-2")
        );
        assert!(std::fs::symlink_metadata(&link).unwrap().is_symlink());
        assert_eq!(*calls.lock().unwrap(), ["refresh-1"]);
    }

    #[tokio::test]
    async fn a_reused_session_takes_the_newer_client_secret_and_entries() {
        let scratch = Scratch::new("reused");
        let path = scratch.0.join("config");
        let expired = test_token(1);
        std::fs::write(&path, kubeconfig(&["dex"], &expired, "refresh-1")).unwrap();
        let secrets = Arc::new(Mutex::new(Vec::new()));
        let exchange: Exchange = {
            let secrets = secrets.clone();
            Arc::new(move |grant: Grant| {
                secrets.lock().unwrap().push(grant.client_secret);
                Box::pin(async {
                    Ok(Issued {
                        id_token: test_token(LATER + 2),
                        refresh_token: Some("refresh-2".into()),
                    })
                })
            })
        };
        let first = layer_in(
            &config(&expired, "refresh-1"),
            std::slice::from_ref(&path),
            exchange.clone(),
        )
        .unwrap();

        // The login was copied to a second user, and its client secret rotated.
        std::fs::write(
            &path,
            kubeconfig(&["dex", "dex-copy"], &expired, "refresh-1"),
        )
        .unwrap();
        let mut rotated = config(&expired, "refresh-1");
        rotated
            .auth_info
            .auth_provider
            .as_mut()
            .unwrap()
            .config
            .insert("client-secret".into(), "rotated".into());
        let second = layer_in(&rotated, std::slice::from_ref(&path), exchange).unwrap();
        assert!(Arc::ptr_eq(&first.session, &second.session));

        call(&first, StatusCode::OK).await.unwrap();
        assert_eq!(*secrets.lock().unwrap(), [Some("rotated".to_owned())]);
        for user in ["dex", "dex-copy"] {
            assert_eq!(
                stored(&path, user).refresh_token.as_deref(),
                Some("refresh-2")
            );
        }
    }

    #[tokio::test]
    async fn an_entry_repurposed_for_another_issuer_is_neither_read_nor_written() {
        let scratch = Scratch::new("repurposed");
        let path = scratch.0.join("config");
        let expired = test_token(1);
        std::fs::write(&path, kubeconfig(&["dex"], &expired, "refresh-1")).unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let layer = layer_in(
            &config(&expired, "refresh-1"),
            std::slice::from_ref(&path),
            provider(calls.clone()),
        )
        .unwrap();

        // The same user name now holds a login to another identity provider.
        let other =
            kubeconfig(&["dex"], &expired, "other-1").replace(ISSUER, "https://other.example.test");
        std::fs::write(&path, &other).unwrap();

        call(&layer, StatusCode::OK).await.unwrap();
        assert_eq!(
            *calls.lock().unwrap(),
            ["refresh-1"],
            "sent another issuer's token"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), other);
    }

    #[test]
    fn other_auth_and_unsaved_logins_stay_with_kube_rs() {
        let scratch = Scratch::new("fallback");
        let path = scratch.0.join("config");
        let token = test_token(LATER);
        std::fs::write(&path, kubeconfig(&["dex"], &token, "refresh-1")).unwrap();
        let paths = [path];
        let exchange = || provider(Arc::default());

        assert!(layer_in(&config(&token, "refresh-1"), &paths, exchange()).is_some());
        // Not in any kubeconfig: nowhere to save a rotated token.
        assert!(layer_in(&config(&token, "refresh-other"), &paths, exchange()).is_none());
        assert!(layer_in(&config(&token, ""), &paths, exchange()).is_none());
        let mut static_token = config(&token, "refresh-1");
        static_token.auth_info.token = Some("static".to_owned().into());
        assert!(layer_in(&static_token, &paths, exchange()).is_none());
        let mut other = config(&token, "refresh-1");
        other.auth_info.auth_provider.as_mut().unwrap().name = "gcp".into();
        assert!(layer_in(&other, &paths, exchange()).is_none());
    }

    #[test]
    fn token_responses_tell_refusals_from_failures() {
        let refused = br#"{"error":"invalid_request","error_description":"Refresh token is invalid or has already been claimed by another client.\u001b[2J"}"#;
        match issued(StatusCode::BAD_REQUEST, refused) {
            Err(ExchangeError::Rejected(reason)) => {
                assert!(reason.starts_with("Refresh token is invalid"), "{reason}");
                assert!(!reason.contains('\u{1b}'), "{reason}");
            }
            _ => panic!("expected a refusal"),
        }
        assert!(matches!(
            issued(StatusCode::UNAUTHORIZED, br#"{"error":"invalid_client"}"#),
            Err(ExchangeError::Failed(_))
        ));
        assert!(matches!(
            issued(StatusCode::BAD_GATEWAY, b"<html>"),
            Err(ExchangeError::Failed(_))
        ));
        assert!(matches!(
            issued(StatusCode::OK, br#"{"access_token":"a"}"#),
            Err(ExchangeError::Failed(_))
        ));
        let Ok(tokens) = issued(StatusCode::OK, br#"{"id_token":"i","refresh_token":""}"#) else {
            panic!("expected tokens")
        };
        assert_eq!(tokens.id_token, "i");
        assert!(tokens.refresh_token.is_none());
    }

    #[tokio::test]
    async fn the_exchange_discovers_the_endpoint_and_posts_the_grant() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}/dex", listener.local_addr().unwrap());
        let token_endpoint = format!("{issuer}/token");
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();
            for body in [
                serde_json::json!({ "token_endpoint": token_endpoint }).to_string(),
                r#"{"id_token":"new-id","refresh_token":"new-refresh"}"#.to_owned(),
            ] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut chunk = [0; 4096];
                    let read = stream.read(&mut chunk).await.unwrap();
                    request.extend_from_slice(&chunk[..read]);
                    let text = String::from_utf8_lossy(&request);
                    if let Some((head, rest)) = text.split_once("\r\n\r\n") {
                        let length = head
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        if rest.len() >= length {
                            break;
                        }
                    }
                }
                requests.push(String::from_utf8(request).unwrap());
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            }
            requests
        });

        let Ok(tokens) = http_exchange(Grant {
            issuer: format!("{issuer}/"),
            client_id: "kube rnetes".into(),
            client_secret: Some("s:cret".into()),
            refresh_token: "old/refresh".into(),
        })
        .await
        else {
            panic!("exchange failed")
        };
        assert_eq!(tokens.id_token, "new-id");
        assert_eq!(tokens.refresh_token.as_deref(), Some("new-refresh"));

        let requests = server.await.unwrap();
        assert!(requests[0].starts_with("GET /dex/.well-known/openid-configuration "));
        let post = &requests[1];
        assert!(post.starts_with("POST /dex/token "), "{post}");
        let basic = STANDARD.encode("kube+rnetes:s%3Acret");
        assert!(
            post.contains(&format!("authorization: Basic {basic}")),
            "{post}"
        );
        assert!(
            post.ends_with("grant_type=refresh_token&refresh_token=old%2Frefresh"),
            "{post}"
        );
    }
}
