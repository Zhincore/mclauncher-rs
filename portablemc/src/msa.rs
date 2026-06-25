//! Microsoft Account authentication for Minecraft accounts.

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Seek};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use std::vec::IntoIter;
use std::{collections::HashMap, fmt::Debug};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngExt;
use rand::distr::Alphanumeric;
use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const PROFILE_URL: &str = "https://api.minecraftservices.com/minecraft/profile";
const DEVICECODE_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode";
const AUTH_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize";
const TOKEN_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token";
const SCOPE: &str = "XboxLive.signin XboxLive.offline_access";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinecraftProfile {
    /// The real UUID of the Minecraft account.
    #[serde(with = "uuid::serde::simple")]
    id: Uuid,
    /// The username of the Minecraft account.
    name: String,
}

/// Microsoft Account authenticator.
///
/// See <https://minecraft.wiki/w/Microsoft_authentication>. Shout out to wiki.vg which no
/// longer exists: <https://wiki.vg/Microsoft_Authentication_Scheme>
#[derive(Debug, Clone)]
pub struct MSAuth {
    app_id: Arc<str>,
    language_code: Option<String>,
}

impl MSAuth {
    /// Create a new authenticator with the given application (client) id.
    pub fn new(app_id: &str) -> Self {
        Self {
            app_id: Arc::from(app_id),
            language_code: None,
        }
    }

    #[inline]
    pub fn app_id(&self) -> &str {
        &self.app_id
    }

    #[inline]
    pub fn language_code(&self) -> Option<&str> {
        self.language_code.as_deref()
    }

    /// Define a specific language code to use for localized messages.
    ///
    /// See <https://en.wikipedia.org/wiki/List_of_ISO_639_language_codes>
    #[inline]
    pub fn set_language_code(&mut self, code: impl Into<String>) -> &mut Self {
        self.language_code = Some(code.into());
        self
    }

    /// Request a device code and if successful, returns the device code auth flow that
    /// contains the user code and the verification URI for that, this flow should be
    /// waited in order to get access to a minecraft authenticator that will ultimately
    /// produce the desired username, UUID and its auth token(s).
    ///
    /// You can opt-in to also request the account's primary email via OpenID MSA scope.
    pub async fn request_device_code(&self) -> Result<DeviceCodeFlow, AuthError> {
        // We request the 'XboxLive.signin' and 'offline_access' scopes that are
        // mandatory for the Minecraft authentication.
        // We could also request email with "openid email" scopes.
        let req = MsDeviceAuthRequest {
            client_id: &self.app_id,
            scope: SCOPE,
            mkt: self.language_code.as_deref(),
        };

        let client = crate::http::builder()
            .build()
            .map_err(AuthError::new_reqwest)?;

        let res = client
            .post(DEVICECODE_URL)
            .form(&req)
            .send()
            .await
            .map_err(AuthError::new_reqwest)?;

        if res.status() != StatusCode::OK {
            return Err(AuthError::InvalidStatus(res.status().as_u16()));
        }

        let res = res
            .json::<MsDeviceAuthSuccess>()
            .await
            .map_err(AuthError::new_reqwest)?;

        Ok(DeviceCodeFlow {
            app_id: Arc::clone(&self.app_id),
            res,
        })
    }

    /// Create standard OAuth flow, requires a redirect uri to a srver that will capture authorization code (can be localhost)
    pub fn create_authorization(&self, redirect_uri: &str, state: Option<&str>) -> OAuthFlow {
        OAuthFlow::new(&self.app_id, redirect_uri, state)
    }
}

/// An authenticated and validated Minecraft account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinecraftAccount {
    pub app_id: String,
    pub refresh_token: String,
    pub access_token: String,
    pub uuid: Uuid,
    pub username: String,
    pub xuid: String,
}
impl MinecraftAccount {
    pub async fn request_profile(&mut self) -> Result<&str, AuthError> {
        let client = crate::http::builder()
            .build()
            .map_err(AuthError::new_reqwest)?;

        match request_minecraft_profile(&client, &self.access_token).await {
            Ok(r) => {
                self.username = r.name;
            }
            Err(err) => match err {
                // Token outdated, retry
                AuthError::OutdatedToken => {
                    self.request_refresh().await?;
                }
                _ => return Err(err),
            },
        };
        Ok(&self.username)
    }

    /// Request account from a refresh_token
    pub async fn request_refresh(&mut self) -> Result<(), AuthError> {
        let req = MsTokenRequest::RefreshToken {
            client_id: &self.app_id,
            scope: Some(SCOPE),
            refresh_token: &self.refresh_token,
            client_secret: None,
        };

        let client = crate::http::builder()
            .build()
            .map_err(AuthError::new_reqwest)?;

        let account = request_account(&client, &req).await?;
        self.access_token = account.access_token;
        self.refresh_token = account.refresh_token;
        self.uuid = account.uuid;
        self.username = account.username;
        self.xuid = account.xuid;

        Ok(())
    }
}

/// Microsoft Account device code flow authenticator.
#[derive(Debug, Clone)]
pub struct DeviceCodeFlow {
    app_id: Arc<str>,
    res: MsDeviceAuthSuccess,
}

impl DeviceCodeFlow {
    #[inline]
    pub fn app_id(&self) -> &str {
        &self.app_id
    }

    #[inline]
    pub fn user_code(&self) -> &str {
        &self.res.user_code
    }

    #[inline]
    pub fn verification_uri(&self) -> &str {
        &self.res.verification_uri
    }

    #[inline]
    pub fn message(&self) -> &str {
        &self.res.message
    }

    /// Wait for the user to authorize via the given user code and verification URI.
    /// If successful the authentication continues and the account is authenticated, if
    /// possible.
    ///
    /// After a successful answer, this flow object should not be used again!
    pub async fn wait(&self) -> Result<MinecraftAccount, AuthError> {
        let req = MsTokenRequest::DeviceCode {
            client_id: &self.app_id,
            device_code: &self.res.device_code,
        };

        let interval = Duration::from_secs(self.res.interval as u64);
        let client = crate::http::builder()
            .build()
            .map_err(AuthError::new_reqwest)?;

        loop {
            tokio::time::sleep(interval).await;
            match request_ms_token(&client, &req, "XboxLive.signin").await? {
                Ok(res) => {
                    let mut account = request_minecraft_account(&client, &res.access_token).await?;
                    account.app_id = self.app_id.to_string();
                    account.refresh_token = res.refresh_token;

                    break Ok(account);
                }
                #[allow(clippy::wildcard_in_or_patterns)]
                Err(res) => match res.error.as_str() {
                    "authorization_pending" => continue,
                    "authorization_declined" => break Err(AuthError::Declined),
                    "expired_token" => break Err(AuthError::TimedOut),
                    "bad_verification_code" | _ => {
                        break Err(AuthError::Unknown(res.error_description));
                    }
                },
            }
        }
    }
}

pub struct OAuthFlow {
    app_id: String,
    redirect_uri: String,

    login_url: String,
    state: String,
    code_verifier: String,
}

impl OAuthFlow {
    pub fn new(app_id: &str, redirect_uri: &str, state: Option<&str>) -> Self {
        let (login_url, state, code_verifier) = get_secure_login_data(app_id, redirect_uri, state);
        Self {
            app_id: app_id.to_string(),
            redirect_uri: redirect_uri.to_string(),

            login_url,
            state,
            code_verifier,
        }
    }

    pub fn login_url(&self) -> &str {
        &self.login_url
    }
    pub fn state(&self) -> &str {
        &self.state
    }

    pub async fn complete(self, code: &str) -> Result<MinecraftAccount, AuthError> {
        let req = MsTokenRequest::AuthorizationCode {
            client_id: &self.app_id,
            scope: Some(SCOPE),
            code,
            redirect_uri: &self.redirect_uri,
            client_secret: None,
            code_verifier: Some(&self.code_verifier),
        };

        let client = crate::http::builder()
            .build()
            .map_err(AuthError::new_reqwest)?;

        request_account(&client, &req).await
    }
}

async fn request_account(
    client: &Client,
    req: &MsTokenRequest<'_>,
) -> Result<MinecraftAccount, AuthError> {
    let ms_auth = request_ms_token(client, req, SCOPE)
        .await?
        .map_err(|e| AuthError::Unknown(e.error_description))?;

    let mut account = request_minecraft_account(client, &ms_auth.access_token).await?;
    account.refresh_token = ms_auth.refresh_token;

    Ok(account)
}

/// Builds a PKCE-enabled login URL, state token, and code verifier.
///
/// The returned tuple is `(login_url, state, code_verifier)`. Store the verifier
/// until the redirect is received, then pass it to [`complete_login`].
/// Stolen from <https://github.com/Star-tears/mc-launcher-core/blob/main/src/auth/microsoft_account.rs>
fn get_secure_login_data(
    client_id: &str,
    redirect_uri: &str,
    state: Option<&str>,
) -> (String, String, String) {
    let (code_verifier, code_challenge, code_challenge_method) = generate_pkce_data();

    let state = match state {
        Some(s) => s.to_string(),
        None => generate_state(),
    };

    let mut parameters = HashMap::new();
    parameters.insert("client_id", client_id);
    parameters.insert("response_type", "code");
    parameters.insert("redirect_uri", redirect_uri);
    parameters.insert("response_mode", "query");
    parameters.insert("scope", SCOPE);
    parameters.insert("state", &state);
    parameters.insert("code_challenge", &code_challenge);
    parameters.insert("code_challenge_method", &code_challenge_method);
    let url = Url::parse(AUTH_URL).expect("Invalid AUTH_URL");
    let login_url = url
        .join(&("?".to_owned() + &serde_urlencoded::to_string(parameters).unwrap()))
        .expect("Failed to build URL");
    (login_url.to_string(), state, code_verifier)
}

/// Stolen from <https://github.com/Star-tears/mc-launcher-core/blob/main/src/auth/microsoft_account.rs>
fn generate_pkce_data() -> (String, String, String) {
    let mut rng = rand::rng();
    let chars: Vec<char> = (0..128)
        .map(|_| match rng.random_range(0..64) {
            0 => '-',
            1 => '_',
            _ => rng.sample(Alphanumeric) as char,
        })
        .collect();
    let code_verifier: String = chars.iter().collect();

    let digest = Sha256::digest(code_verifier.as_bytes());
    let code_challenge = URL_SAFE_NO_PAD.encode(digest);
    code_challenge.trim_end_matches('=').to_string();
    let code_challenge_method = "S256".to_string();

    (code_verifier, code_challenge, code_challenge_method)
}

/// Generates a random OAuth state token.
/// Stolen from <https://github.com/Star-tears/mc-launcher-core/blob/main/src/auth/microsoft_account.rs>
fn generate_state() -> String {
    let mut rng = rand::rng();
    let chars: Vec<char> = (0..16)
        .map(|_| match rng.random_range(0..64) {
            0 => '-',
            1 => '_',
            _ => rng.sample(Alphanumeric) as char,
        })
        .collect();
    let state: String = chars.iter().collect();
    state
}

/// Request a Minecraft Account token from the given request.
async fn request_ms_token(
    client: &Client,
    req: &MsTokenRequest<'_>,
    expected_scope: &str,
) -> Result<std::result::Result<MsTokenSuccess, MsAuthError>, AuthError> {
    let res = client
        .post(TOKEN_URL)
        .form(req)
        .send()
        .await
        .map_err(AuthError::new_reqwest)?;

    match res.status() {
        StatusCode::OK => {
            let res = res
                .json::<MsTokenSuccess>()
                .await
                .map_err(AuthError::new_reqwest)?;

            if res.token_type != "Bearer" {
                return Err(AuthError::Unknown(format!(
                    "Unexpected token type: {}",
                    res.token_type
                )));
            } else if res.scope != expected_scope {
                return Err(AuthError::Unknown(format!(
                    "Unexpected scope: {}",
                    res.scope
                )));
            }

            Ok(Ok(res))
        }
        StatusCode::BAD_REQUEST => Ok(Err(res
            .json::<MsAuthError>()
            .await
            .map_err(AuthError::new_reqwest)?)),
        status => Err(AuthError::InvalidStatus(status.as_u16())),
    }
}

/// Full procedure to gain access to a real Minecraft account from a given MSA token.
/// The returned account has no client id, no refresh token and no email.
async fn request_minecraft_account(
    client: &Client,
    ms_auth_token: &str,
) -> Result<MinecraftAccount, AuthError> {
    // XBL authentication and authorization...
    let user_res = request_xbl_user(client, ms_auth_token).await?;
    let xsts_res = request_xbl_xsts(client, &user_res.token).await?;

    // Now checking coherency...
    if user_res.display_claims.xui.is_empty()
        || user_res.display_claims.xui != xsts_res.display_claims.xui
    {
        return Err(AuthError::Unknown(
            "Invalid or incoherent display claims.".to_string(),
        ));
    }

    let user_hash = xsts_res.display_claims.xui[0].uhs.as_str();
    let xsts_token = xsts_res.token.as_str();

    // Minecraft with XBL...
    let mc_res = request_minecraft_with_xbl(client, user_hash, xsts_token).await?;
    // Minecraft profile...
    let profile_res = request_minecraft_profile(client, &mc_res.access_token).await?;

    Ok(MinecraftAccount {
        app_id: String::new(),
        refresh_token: String::new(),
        access_token: mc_res.access_token,
        uuid: profile_res.id,
        username: profile_res.name,
        xuid: user_hash.to_string(),
    })
}

async fn request_xbl_user(client: &Client, ms_auth_token: &str) -> Result<XblSuccess, AuthError> {
    let req = json!({
        "Properties": {
            "AuthMethod": "RPS",
            "SiteName": "user.auth.xboxlive.com",
            "RpsTicket": format!("d={ms_auth_token}"),
        },
        "RelyingParty": "http://auth.xboxlive.com",
        "TokenType": "JWT"
    });

    let res = client
        .post("https://user.auth.xboxlive.com/user/authenticate")
        .json(&req)
        .send()
        .await
        .map_err(AuthError::new_reqwest)?;

    match res.status() {
        StatusCode::OK => Ok(res
            .json::<XblSuccess>()
            .await
            .map_err(AuthError::new_reqwest)?),
        status => Err(AuthError::InvalidStatus(status.as_u16())),
    }
}

async fn request_xbl_xsts(client: &Client, xbl_user_token: &str) -> Result<XblSuccess, AuthError> {
    let req = json!({
        "Properties": {
            "SandboxId": "RETAIL",
            "UserTokens": [xbl_user_token]
        },
        "RelyingParty": "rp://api.minecraftservices.com/",
        "TokenType": "JWT"
    });

    let res = client
        .post("https://xsts.auth.xboxlive.com/xsts/authorize")
        .json(&req)
        .send()
        .await
        .map_err(AuthError::new_reqwest)?;

    match res.status() {
        StatusCode::OK => Ok(res
            .json::<XblSuccess>()
            .await
            .map_err(AuthError::new_reqwest)?),
        StatusCode::UNAUTHORIZED => {
            let res = res
                .json::<XblError>()
                .await
                .map_err(AuthError::new_reqwest)?;
            Err(AuthError::Unknown(res.message))
        }
        status => Err(AuthError::InvalidStatus(status.as_u16())),
    }
}

async fn request_minecraft_with_xbl(
    client: &Client,
    user_hash: &str,
    xsts_token: &str,
) -> Result<MinecraftWithXblSuccess, AuthError> {
    let req = json!({
        "identityToken": format!("XBL3.0 x={user_hash};{xsts_token}"),
    });

    let res = client
        .post("https://api.minecraftservices.com/authentication/login_with_xbox")
        .json(&req)
        .send()
        .await
        .map_err(AuthError::new_reqwest)?;

    let mc_res = match res.status() {
        StatusCode::OK => res
            .json::<MinecraftWithXblSuccess>()
            .await
            .map_err(AuthError::new_reqwest)?,
        status => return Err(AuthError::InvalidStatus(status.as_u16())),
    };

    if mc_res.token_type != "Bearer" {
        return Err(AuthError::Unknown(format!(
            "Unexpected token type: {}",
            mc_res.token_type
        )));
    }

    Ok(mc_res)
}

async fn request_minecraft_profile(
    client: &Client,
    access_token: &str,
) -> Result<MinecraftProfile, AuthError> {
    let res = client
        .get(PROFILE_URL)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(AuthError::new_reqwest)?;

    match res.status() {
        StatusCode::OK => Ok(res
            .json::<MinecraftProfile>()
            .await
            .map_err(AuthError::new_reqwest)?),
        StatusCode::FORBIDDEN => {
             Err(AuthError::Unknown(
                "Forbidden access to api.minecraftservices.com, likely because the application lacks approval from Mojang, see https://minecraft.wiki/w/Microsoft_authentication.".to_string()))
        }
        StatusCode::UNAUTHORIZED =>  Err(AuthError::OutdatedToken),
        StatusCode::NOT_FOUND =>  Err(AuthError::DoesNotOwnGame),
        status =>  Err(AuthError::InvalidStatus(status.as_u16())),
    }
}

/// The error type containing one error for each failed entry in a download batch.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum AuthError {
    /// Authorization declined by the user.
    #[error("declined")]
    Declined,
    /// Time out of the authentication flow.
    #[error("timed out")]
    TimedOut,
    /// When refreshing the Minecraft profile, this tells that the token is outdated, but
    /// the caller can still try to refresh it.
    #[error("outdated token")]
    OutdatedToken,
    #[error("does not own the game")]
    DoesNotOwnGame,
    /// An unknown HTTP status has been received.
    #[error("invalid status: {0}")]
    InvalidStatus(u16),
    /// An unknown, unhandled error happened.
    #[error("unknown: {0}")]
    Unknown(String),
    /// A generic error type for internal and third-party errors that may change depending
    /// on the actual implementation.
    ///
    /// The current implementation yields the following error types:
    ///
    /// - [`reqwest::Error`] for any error related to HTTP requests.
    ///
    /// - [`jsonwebtoken::errors::Error`] for any error related to decoding JWTs.
    #[error("internal: {0}")]
    Internal(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl AuthError {
    #[inline]
    fn new_reqwest(e: reqwest::Error) -> Self {
        Self::Internal(Box::new(e))
    }
}

/// (URL encoded)
#[derive(Debug, Clone, serde::Serialize)]
struct MsDeviceAuthRequest<'a> {
    client_id: &'a str,
    scope: &'a str,
    mkt: Option<&'a str>,
}

/// (JSON)
#[derive(Debug, Clone, Deserialize)]
struct MsDeviceAuthSuccess {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[allow(unused)]
    expires_in: u32,
    interval: u32,
    message: String,
}

/// (URL encoded)
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "grant_type")]
enum MsTokenRequest<'a> {
    #[serde(rename = "urn:ietf:params:oauth:grant-type:device_code")]
    DeviceCode {
        client_id: &'a str,
        device_code: &'a str,
    },
    #[serde(rename = "authorization_code")]
    AuthorizationCode {
        client_id: &'a str,
        scope: Option<&'a str>,
        code: &'a str,
        redirect_uri: &'a str,
        client_secret: Option<&'a str>,
        code_verifier: Option<&'a str>,
    },
    #[serde(rename = "refresh_token")]
    RefreshToken {
        client_id: &'a str,
        scope: Option<&'a str>,
        refresh_token: &'a str,
        client_secret: Option<&'a str>,
    },
}

/// (JSON)
#[derive(Debug, Clone, Deserialize)]
struct MsTokenSuccess {
    /// Always "Bearer"
    token_type: String,
    scope: String,
    #[allow(unused)]
    expires_in: u32,
    access_token: String,
    /// Issued if the original scope parameter included the openid scope
    #[allow(unused)]
    id_token: Option<String>,
    /// Issued if the original scope parameter included offline_access.
    refresh_token: String,
}

/// (JSON) Generic authentication error returned by the API.
#[derive(Debug, Clone, Deserialize)]
struct MsAuthError {
    error: String,
    error_description: String,
    #[allow(unused)]
    trace_id: String,
    #[allow(unused)]
    correlation_id: String,
    #[allow(unused)]
    error_uri: Option<String>,
}

/// (JSON)
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct XblSuccess {
    display_claims: XblDisplayClaims,
    #[allow(unused)]
    issue_instant: String,
    #[allow(unused)]
    not_after: String,
    token: String,
}

/// (JSON)
#[derive(Debug, Clone, Deserialize)]
struct XblDisplayClaims {
    xui: Vec<XblXui>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct XblXui {
    uhs: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[allow(unused)]
struct XblError {
    identity: String,
    x_err: u32,
    message: String,
    redirect: String,
}

#[derive(Debug, Clone, Deserialize)]
struct MinecraftWithXblSuccess {
    /// Some UUID, not the account's player UUID.
    #[allow(unused)]
    username: String,
    /// The actual Minecraft access token to use to launch the game.
    access_token: String,
    token_type: String,
    #[allow(unused)]
    expires_in: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(unused)]
struct OpenIdToken {
    nonce: Option<String>,
    email: Option<String>,
}

/// A file-backed database for storing accounts. It allows storing and retrieving
/// accounts atomically (using shared read and exclusive write property of the underlying
/// filesystem).
#[derive(Debug)]
pub struct Database {
    file: PathBuf,
}

impl Database {
    /// Create a new database at the given location, the parent directory may not exists.
    /// This will not actually load the database contents, but it will
    pub fn new<P: Into<PathBuf>>(file: P) -> Self {
        Self { file: file.into() }
    }

    /// Get the file path.
    pub fn file(&self) -> &Path {
        &self.file
    }

    /// Internal function to load the database data.
    fn load(&self) -> Result<Option<DatabaseData>, DatabaseError> {
        let reader = match File::open(&self.file) {
            Ok(reader) => reader,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        let data = serde_json::from_reader::<_, DatabaseData>(BufReader::new(reader))
            .map_err(|e| DatabaseError::Corrupted.map_json_io(e))?;

        Ok(Some(data))
    }

    /// Internal function to load the database data
    fn load_and_store<F, T>(&self, func: F) -> Result<T, DatabaseError>
    where
        F: for<'a> FnOnce(&'a mut DatabaseData, &'a mut bool) -> T,
    {
        if let Some(parent_dir) = self.file.parent() {
            fs::create_dir_all(parent_dir)?;
        }

        let mut rw = File::options()
            .write(true)
            .read(true)
            .create(true)
            .truncate(false)
            .open(&self.file)?;

        let mut data;

        // If the file is empty, don't try to decode it but create a new empty database!
        if rw.read(&mut [0; 1])? == 0 {
            data = DatabaseData {
                accounts: Vec::new(),
            };
        } else {
            // Rewind to re-read it from start!
            rw.rewind()?;

            data = serde_json::from_reader::<_, DatabaseData>(BufReader::new(&mut rw))
                .map_err(|e| DatabaseError::Corrupted.map_json_io(e))?;
        }

        let mut save = false;
        let ret = func(&mut data, &mut save);

        if save {
            rw.rewind()?;
            rw.set_len(0)?;

            serde_json::to_writer(BufWriter::new(rw), &data)
                .map_err(|_| DatabaseError::WriteFailed)?;
        }

        Ok(ret)
    }

    /// Load every account in this database and return an iterator over all of them.
    pub fn load_iter(&self) -> Result<IntoIter<MinecraftAccount>, DatabaseError> {
        self.load().map(|data| {
            data.map(|data| data.accounts)
                .unwrap_or_default()
                .into_iter()
        })
    }

    /// Load an account from its UUID.
    pub fn load_from_uuid(&self, uuid: Uuid) -> Result<Option<MinecraftAccount>, DatabaseError> {
        self.load().map(|data| {
            data.and_then(|data| data.accounts.into_iter().find(|acc| acc.uuid == uuid))
        })
    }

    /// Load an account from its username, because a username it not guaranteed to be
    /// unique, in case of non-freshed sessions that keep old .
    pub fn load_from_username(
        &self,
        username: &str,
    ) -> Result<Option<MinecraftAccount>, DatabaseError> {
        self.load().map(|data| {
            data.and_then(|data| {
                data.accounts
                    .into_iter()
                    .find(|acc| acc.username == username)
            })
        })
    }

    /// Remove the given account from its UUID, if existing, and save the database without
    /// it.
    ///
    /// If the account doesn't exist, the database is not touch, only read.
    pub fn remove_from_uuid(&self, uuid: Uuid) -> Result<Option<MinecraftAccount>, DatabaseError> {
        self.load_and_store(|data, save| {
            let index = data.accounts.iter().position(|acc| acc.uuid == uuid)?;
            *save = true;
            Some(data.accounts.remove(index))
        })
    }

    /// Remove the given account from its username, if existing, and save the database
    /// without it. Note that a username is not guaranteed to be unique, so only the first
    /// matching account is removed.
    ///
    /// If the account doesn't exist, the database is not touch, only read.
    pub fn remove_from_username(
        &self,
        username: &str,
    ) -> Result<Option<MinecraftAccount>, DatabaseError> {
        self.load_and_store(|data, save| {
            let index = data
                .accounts
                .iter()
                .position(|acc| acc.username == username)?;
            *save = true;
            Some(data.accounts.remove(index))
        })
    }

    /// Store the given account in this database, overwrite any previously stored account
    /// with the same UUID.
    pub fn store(&self, account: MinecraftAccount) -> Result<(), DatabaseError> {
        self.load_and_store(|data, save| {
            *save = true;
            if let Some(index) = data
                .accounts
                .iter()
                .position(|acc| acc.uuid == account.uuid)
            {
                data.accounts[index] = account;
            } else {
                data.accounts.push(account);
            }
        })
    }
}

/// The error type containing one error for each failed entry in a download batch.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum DatabaseError {
    /// An underlying I/O error when opening the database file.
    #[error("io: {0}")]
    Io(#[from] io::Error),
    /// The database is corrupted and nothing can be done about it automatically, you
    /// can move the file to a backup location before retrying.
    #[error("corrupted")]
    Corrupted,
    #[error("write failed")]
    WriteFailed,
}

impl DatabaseError {
    /// Internal function to map this error type and replace it by [`Self::Io`] whenever
    /// the given serde error has an underlying I/O error.
    fn map_json_io(self, value: serde_json::Error) -> Self {
        if let Some(kind) = value.io_error_kind() {
            Self::Io(kind.into())
        } else {
            self
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct DatabaseData {
    accounts: Vec<MinecraftAccount>,
}
