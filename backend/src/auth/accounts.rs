use super::{
    Role, User,
    access::{SESSION, Session, client_ip, issue_session},
    audit, forbidden, hash, optional_env, secret_env,
};
use crate::{ApiError, ApiResult, App};
use anyhow::{Context, Result, ensure};
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use axum::{
    Extension, Json,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{PgConnection, PgPool};
use std::net::{IpAddr, SocketAddr};
use subtle::ConstantTimeEq;
use uuid::Uuid;

fn argon2() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(19 * 1024, 2, 1, None).unwrap(),
    )
}

pub fn password_hash(password: &str) -> Result<String> {
    let salt = SaltString::encode_b64(&super::random_bytes()?).map_err(anyhow::Error::msg)?;
    Ok(argon2()
        .hash_password(password.as_bytes(), &salt)
        .map_err(anyhow::Error::msg)?
        .to_string())
}

fn verify(password: &str, value: &str) -> bool {
    PasswordHash::new(value).is_ok_and(|encoded| {
        argon2()
            .verify_password(password.as_bytes(), &encoded)
            .is_ok()
    })
}

fn password_policy(password: &str) -> ApiResult<()> {
    const COMMON: &[&str] = &[
        "password1234",
        "password12345",
        "123456789012",
        "1234567890123",
        "qwertyuiop12",
        "qwerty123456",
        "admin1234567",
        "letmein12345",
        "changeme1234",
        "passwordpassword",
        "correcthorsebatterystaple",
    ];
    if password.len() > 1024
        || password.chars().count() < 12
        || password.chars().all(char::is_whitespace)
        || COMMON
            .iter()
            .any(|common| password.eq_ignore_ascii_case(common))
    {
        return Err(ApiError::bad(
            "Choose an uncommon password with at least 12 characters and at most 1024 bytes.",
        ));
    }
    Ok(())
}

pub fn email(value: &str) -> ApiResult<String> {
    let value = value.trim();
    if value.len() <= 254
        && value.is_ascii()
        && !value
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        && value.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty()
                && !domain.is_empty()
                && domain.split('.').all(|label| {
                    !label.is_empty()
                        && label
                            .as_bytes()
                            .first()
                            .is_some_and(u8::is_ascii_alphanumeric)
                        && label
                            .as_bytes()
                            .last()
                            .is_some_and(u8::is_ascii_alphanumeric)
                        && label
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
        })
    {
        return Ok(value.to_ascii_lowercase());
    }
    Err(ApiError::bad("Enter a valid email address."))
}

pub fn name(value: &str) -> ApiResult<&str> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > 100 || value.chars().any(char::is_control) {
        return Err(ApiError::bad(
            "Enter a display name between 1 and 100 characters.",
        ));
    }
    Ok(value)
}

async fn password_work<T: Send + 'static>(
    app: &App,
    work: impl FnOnce() -> T + Send + 'static,
) -> ApiResult<T> {
    // Keep the permit with the blocking work if the request is cancelled.
    let permit = app
        .0
        .auth
        .password_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            ApiError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Sign-in is busy. Try again shortly.".into(),
            )
        })?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
    .map_err(anyhow::Error::from)
    .map_err(ApiError::from)
}

async fn new_hash(app: &App, password: String) -> ApiResult<String> {
    password_policy(&password)?;
    Ok(password_work(app, move || password_hash(&password)).await??)
}

pub async fn lock_users(connection: &mut PgConnection) -> ApiResult<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(721965052250000013)")
        .execute(connection)
        .await?;
    Ok(())
}

async fn has_users(connection: &mut PgConnection) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS (SELECT FROM auth_users)")
        .fetch_one(connection)
        .await
}

pub async fn lock_user(connection: &mut PgConnection, id: Uuid) -> ApiResult<Option<User>> {
    Ok(sqlx::query_as(
        "SELECT id,email,display_name,role,disabled,password_hash IS NOT NULL AS has_password FROM auth_users WHERE id=$1 FOR UPDATE"
    )
    .bind(id)
    .fetch_optional(connection)
    .await?)
}

pub async fn user_by_email(connection: &mut PgConnection, email: &str) -> ApiResult<Option<User>> {
    Ok(sqlx::query_as(
        "SELECT id,email,display_name,role,disabled,password_hash IS NOT NULL AS has_password FROM auth_users WHERE email=$1 FOR UPDATE"
    )
    .bind(email)
    .fetch_optional(connection)
    .await?)
}

pub async fn insert_user(
    connection: &mut PgConnection,
    email: &str,
    name: &str,
    role: Role,
    password: Option<&str>,
) -> ApiResult<User> {
    Ok(sqlx::query_as(
        "INSERT INTO auth_users(id,email,display_name,role,password_hash) VALUES($1,$2,$3,$4,$5) RETURNING id,email,display_name,role,disabled,password_hash IS NOT NULL AS has_password"
    ).bind(Uuid::now_v7()).bind(email).bind(name).bind(role).bind(password).fetch_one(connection).await?)
}

pub async fn initialize(app: &App, generated_code: Option<String>, recover: bool) -> Result<()> {
    let pool = &app.0.database.primary;
    if !recover && has_users(&mut *pool.acquire().await?).await? {
        return Ok(());
    }
    let email_value = optional_env("CERTHIA_ADMIN_EMAIL");
    let password = secret_env("CERTHIA_ADMIN_PASSWORD")?;
    let (email_value, password) = match (email_value, password) {
        (Some(email), Some(password)) => (email, password),
        (None, None) if !recover => {
            ensure!(
                app.0.auth.local,
                "Initialize the first administrator before disabling local login"
            );
            if let Some(code) = generated_code {
                eprintln!("Certhia first-run setup code: {code}");
            }
            return Ok(());
        }
        _ => anyhow::bail!(
            "Set CERTHIA_ADMIN_EMAIL and CERTHIA_ADMIN_PASSWORD or CERTHIA_ADMIN_PASSWORD_FILE"
        ),
    };
    let email = email(&email_value)?;
    password_policy(&password)?;
    let encoded = password_hash(&password)?;
    let mut tx = pool.begin().await?;
    lock_users(&mut tx).await?;
    if recover {
        let user = user_by_email(&mut tx, &email)
            .await?
            .filter(|user| !user.disabled && user.role == Role::Admin)
            .context("Recovery requires an enabled administrator")?;
        set_password(&mut tx, user.id, &encoded).await?;
        audit(
            &mut tx,
            "auth.password.recovered",
            Some(user.id),
            None,
            "server console",
        )
        .await?;
    } else if !has_users(&mut tx).await? {
        let user = insert_user(
            &mut tx,
            &email,
            "Administrator",
            Role::Admin,
            Some(&encoded),
        )
        .await?;
        audit(
            &mut tx,
            "auth.user.created",
            Some(user.id),
            None,
            "environment bootstrap",
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn status(State(app): State<App>) -> ApiResult<Json<Value>> {
    let has_users = has_users(&mut *app.0.database.primary.acquire().await?).await?;
    let providers: Vec<_> = app
        .0
        .auth
        .providers
        .iter()
        .map(|provider| json!({ "id": provider.id, "name": provider.name }))
        .collect();
    Ok(Json(
        json!({ "local": app.0.auth.local, "setupRequired": app.0.auth.local && !has_users, "providers": providers }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Setup {
    email: String,
    display_name: String,
    password: String,
    setup_code: String,
}

pub async fn setup(
    State(app): State<App>,
    peer: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<Setup>,
) -> ApiResult<Response> {
    let pool = &app.0.database.primary;
    if !app.0.auth.local || has_users(&mut *pool.acquire().await?).await? {
        return Err(forbidden());
    }
    rate_limit(
        pool,
        "setup-ip",
        &client_ip(&app, peer, &headers).to_string(),
        20,
    )
    .await?;
    if !app
        .0
        .auth
        .setup_hash
        .is_some_and(|expected| expected.ct_eq(&hash(input.setup_code.as_bytes())).into())
    {
        return Err(forbidden());
    }
    let email = email(&input.email)?;
    let name = name(&input.display_name)?;
    let encoded = new_hash(&app, input.password).await?;
    let mut tx = pool.begin().await?;
    lock_users(&mut tx).await?;
    if has_users(&mut tx).await? {
        return Err(forbidden());
    }
    let user = insert_user(&mut tx, &email, name, Role::Admin, Some(&encoded)).await?;
    audit(
        &mut tx,
        "auth.user.created",
        Some(user.id),
        Some(user.id),
        "browser bootstrap",
    )
    .await?;
    let cookie = issue_session(&app, &mut tx, &headers, &user, "setup").await?;
    tx.commit().await?;
    Ok(([(header::SET_COOKIE, cookie)], Json(user)).into_response())
}

#[derive(Deserialize)]
pub struct Login {
    email: String,
    password: String,
}

pub async fn rate_limit(pool: &PgPool, scope: &str, value: &str, limit: i32) -> ApiResult<()> {
    let attempts: i32 = sqlx::query_scalar(
        "INSERT INTO auth_rate_limits(key,attempts,expires) VALUES($1,1,now()+interval '5 minutes')
         ON CONFLICT(key) DO UPDATE SET
            attempts=CASE WHEN auth_rate_limits.expires<=now() THEN 1 ELSE LEAST(auth_rate_limits.attempts+1,$2+1) END,
            expires=CASE WHEN auth_rate_limits.expires<=now() THEN excluded.expires ELSE auth_rate_limits.expires END
         RETURNING attempts",
    )
    .bind(hash(format!("{scope}:{value}").as_bytes()).as_slice()).bind(limit)
    .fetch_one(pool).await?;
    if attempts > limit {
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts. Try again in a few minutes.".into(),
        ));
    }
    Ok(())
}

fn credential_error() -> ApiError {
    ApiError(
        StatusCode::UNAUTHORIZED,
        "Email or password is incorrect.".into(),
    )
}

pub async fn login(
    State(app): State<App>,
    peer: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<Login>,
) -> ApiResult<Response> {
    if !app.0.auth.local {
        return Err(forbidden());
    }
    let email = input.email.trim().to_ascii_lowercase();
    let pool = &app.0.database.primary;
    let ip: IpAddr = client_ip(&app, peer, &headers);
    rate_limit(pool, "login-ip", &ip.to_string(), 50).await?;
    rate_limit(pool, "login-account", &email, 10).await?;
    let credentials: Option<(Uuid, Option<String>, bool)> =
        sqlx::query_as("SELECT id,password_hash,disabled FROM auth_users WHERE email=$1")
            .bind(email)
            .fetch_optional(pool)
            .await?;
    let real_hash = credentials
        .as_ref()
        .filter(|(_, _, disabled)| !disabled)
        .and_then(|(_, hash, _)| hash.as_ref());
    let encoded = real_hash.unwrap_or(&app.0.auth.dummy_hash).clone();
    let password = input.password;
    let valid = password_work(&app, move || {
        let bounded = if password.len() <= 1024 {
            &password
        } else {
            ""
        };
        verify(bounded, &encoded) && password.len() <= 1024
    })
    .await?;
    if !valid || real_hash.is_none() {
        audit(
            &mut *pool.acquire().await?,
            "auth.login.failed",
            None,
            None,
            "local",
        )
        .await?;
        return Err(credential_error());
    }
    let (id, prior, _) = credentials.expect("validated account");
    let mut tx = pool.begin().await?;
    let user = lock_user(&mut tx, id).await?.filter(|user| !user.disabled);
    let current: Option<String> = password_for(&mut tx, id).await?;
    if let Some(user) = user
        && same_hash(current.as_deref(), prior.as_deref())
    {
        let cookie = issue_session(&app, &mut tx, &headers, &user, "local").await?;
        tx.commit().await?;
        return Ok(([(header::SET_COOKIE, cookie)], Json(user)).into_response());
    }
    audit(&mut tx, "auth.login.failed", None, None, "local").await?;
    tx.commit().await?;
    Err(credential_error())
}

fn same_hash(a: Option<&str>, b: Option<&str>) -> bool {
    matches!((a, b), (Some(a), Some(b)) if bool::from(a.as_bytes().ct_eq(b.as_bytes())))
}

async fn password_for(connection: &mut PgConnection, id: Uuid) -> ApiResult<Option<String>> {
    Ok(
        sqlx::query_scalar("SELECT password_hash FROM auth_users WHERE id=$1")
            .bind(id)
            .fetch_optional(connection)
            .await?
            .flatten(),
    )
}

pub async fn me(State(app): State<App>, Extension(session): Extension<Session>) -> Json<Value> {
    Json(json!({
        "user": session.user,
        "local": app.0.auth.local,
        "oidcEmailLinking": app.0.auth.providers.iter().any(|provider| provider.link_by_email)
    }))
}

pub async fn logout(
    State(app): State<App>,
    Extension(session): Extension<Session>,
) -> ApiResult<Response> {
    let mut tx = app.0.database.primary.begin().await?;
    sqlx::query("DELETE FROM auth_sessions WHERE token_hash=$1")
        .bind(session.hash.as_slice())
        .execute(&mut *tx)
        .await?;
    audit(
        &mut tx,
        "auth.logout",
        Some(session.user.id),
        Some(session.user.id),
        "",
    )
    .await?;
    tx.commit().await?;
    Ok(clear_session(&app))
}

fn clear_session(app: &App) -> Response {
    (
        StatusCode::NO_CONTENT,
        [(header::SET_COOKIE, app.0.auth.cookie(SESSION, "", 0))],
    )
        .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordChange {
    current_password: String,
    new_password: String,
}

pub async fn change_password(
    State(app): State<App>,
    Extension(session): Extension<Session>,
    Json(input): Json<PasswordChange>,
) -> ApiResult<Response> {
    if !app.0.auth.local || !session.user.has_password {
        return Err(forbidden());
    }
    password_policy(&input.new_password)?;
    let pool = &app.0.database.primary;
    let id = session.user.id;
    rate_limit(pool, "password-change", &id.to_string(), 10).await?;
    let prior = password_for(&mut *pool.acquire().await?, id)
        .await?
        .ok_or_else(forbidden)?;
    let candidate = prior.clone();
    let encoded = password_work(&app, move || {
        if input.current_password.len() <= 1024 && verify(&input.current_password, &candidate) {
            password_hash(&input.new_password).map(Some)
        } else {
            Ok(None)
        }
    })
    .await??
    .ok_or_else(|| ApiError::bad("Current password is incorrect."))?;
    let mut tx = pool.begin().await?;
    let user = lock_user(&mut tx, id).await?.filter(|user| !user.disabled);
    let current = password_for(&mut tx, id).await?;
    let active = session.is_active(&mut *tx).await?;
    if !active || user.is_none() || !same_hash(current.as_deref(), Some(&prior)) {
        return Err(super::unauthorized());
    }
    set_password(&mut tx, id, &encoded).await?;
    audit(&mut tx, "auth.password.changed", Some(id), Some(id), "").await?;
    tx.commit().await?;
    Ok(clear_session(&app))
}

async fn set_password(connection: &mut PgConnection, id: Uuid, encoded: &str) -> ApiResult<()> {
    sqlx::query("UPDATE auth_users SET password_hash=$2 WHERE id=$1")
        .bind(id)
        .bind(encoded)
        .execute(&mut *connection)
        .await?;
    revoke_sessions(connection, id).await
}

async fn revoke_sessions(connection: &mut PgConnection, id: Uuid) -> ApiResult<()> {
    sqlx::query("DELETE FROM auth_sessions WHERE user_id=$1")
        .bind(id)
        .execute(connection)
        .await?;
    Ok(())
}

pub async fn list(
    State(app): State<App>,
    Query(page): Query<crate::IdPage>,
) -> ApiResult<crate::List<User>> {
    let limit = page.limit()?;
    let rows = sqlx::query_as(
        "SELECT id,email,display_name,role,disabled,password_hash IS NOT NULL AS has_password FROM auth_users WHERE ($1::uuid IS NULL OR id>$1) ORDER BY id LIMIT $2")
        .bind(page.cursor).bind(limit + 1).fetch_all(&app.0.database.primary).await?;
    crate::page_rows(rows, limit, |user: &User| user.id.to_string())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Create {
    email: String,
    display_name: String,
    role: Role,
    password: Option<String>,
}

async fn admin_transaction<'a>(
    pool: &'a PgPool,
    session: &Session,
) -> ApiResult<sqlx::Transaction<'a, sqlx::Postgres>> {
    let mut tx = pool.begin().await?;
    lock_users(&mut tx).await?;
    if !session.is_active(&mut *tx).await? {
        return Err(super::unauthorized());
    }
    Ok(tx)
}

pub async fn create(
    State(app): State<App>,
    Extension(session): Extension<Session>,
    Json(input): Json<Create>,
) -> ApiResult<(StatusCode, Json<User>)> {
    let email = email(&input.email)?;
    let name = name(&input.display_name)?;
    let encoded = match input.password {
        Some(password) if app.0.auth.local => Some(new_hash(&app, password).await?),
        Some(_) => return Err(forbidden()),
        None if app
            .0
            .auth
            .providers
            .iter()
            .any(|provider| provider.link_by_email) =>
        {
            None
        }
        None => {
            return Err(ApiError::bad(
                "Set an initial password or configure OIDC email linking.",
            ));
        }
    };
    let mut tx = admin_transaction(&app.0.database.primary, &session).await?;
    let user = insert_user(&mut tx, &email, name, input.role, encoded.as_deref()).await?;
    audit(
        &mut tx,
        "auth.user.created",
        Some(user.id),
        Some(session.user.id),
        "",
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(user)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Update {
    role: Role,
    disabled: bool,
    display_name: Option<String>,
    new_password: Option<String>,
}

pub async fn update(
    State(app): State<App>,
    Extension(session): Extension<Session>,
    Path(id): Path<Uuid>,
    Json(input): Json<Update>,
) -> ApiResult<Json<User>> {
    let encoded = match input.new_password {
        Some(password) if app.0.auth.local && session.user.id != id => {
            Some(new_hash(&app, password).await?)
        }
        Some(_) => return Err(forbidden()),
        None => None,
    };
    let mut tx = admin_transaction(&app.0.database.primary, &session).await?;
    let old = lock_user(&mut tx, id)
        .await?
        .ok_or_else(|| ApiError::missing("User not found."))?;
    if !old.disabled && old.role == Role::Admin && (input.disabled || input.role != Role::Admin) {
        let another_admin: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT FROM auth_users WHERE id<>$1 AND role='admin' AND NOT disabled)",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        if !another_admin {
            return Err(ApiError::bad("Keep at least one enabled administrator."));
        }
    }
    let display_name = input
        .display_name
        .as_deref()
        .map(name)
        .transpose()?
        .unwrap_or(&old.display_name);
    let user = sqlx::query_as::<_, User>(
        "UPDATE auth_users SET role=$2,disabled=$3,display_name=$4 WHERE id=$1 RETURNING id,email,display_name,role,disabled,password_hash IS NOT NULL AS has_password"
    ).bind(id).bind(input.role).bind(input.disabled).bind(display_name).fetch_one(&mut *tx).await?;
    let actor = Some(session.user.id);
    if let Some(encoded) = encoded {
        if !old.has_password {
            return Err(ApiError::bad("This account uses single sign-on."));
        }
        set_password(&mut tx, id, &encoded).await?;
        audit(&mut tx, "auth.password.reset", Some(id), actor, "").await?;
    } else if old.role != user.role || old.disabled != user.disabled {
        revoke_sessions(&mut tx, id).await?;
    }
    if old.role != user.role {
        let detail = format!("{:?} → {:?}", old.role, user.role);
        audit(&mut tx, "auth.role.changed", Some(id), actor, &detail).await?;
    }
    let event = match (old.disabled, user.disabled) {
        (false, true) => "auth.user.disabled",
        (true, false) => "auth.user.enabled",
        _ => "auth.user.updated",
    };
    audit(&mut tx, event, Some(id), actor, "").await?;
    tx.commit().await?;
    Ok(Json(user))
}

pub async fn revoke(
    State(app): State<App>,
    Extension(session): Extension<Session>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let mut tx = admin_transaction(&app.0.database.primary, &session).await?;
    lock_user(&mut tx, id)
        .await?
        .ok_or_else(|| ApiError::missing("User not found."))?;
    revoke_sessions(&mut tx, id).await?;
    audit(
        &mut tx,
        "auth.sessions.revoked",
        Some(id),
        Some(session.user.id),
        "",
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords_use_owasp_argon2id_and_unique_salts() {
        let password = "alpine-depot-paper-ink";
        let encoded = password_hash(password).unwrap();
        assert!(encoded.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert_ne!(password_hash(password).unwrap(), encoded);
        assert!(verify(password, &encoded));
        assert!(!verify("wrong", &encoded));
        assert!(password_policy(password).is_ok());
        assert!(password_policy("PASSWORD1234").is_err());
        assert!(password_policy("too-short").is_err());
    }
}
