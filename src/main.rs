use std::collections::HashMap;
use std::convert::Infallible;

use axum::{
    extract::Form,
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::get,
    Router,
};

use axum_login::{
    login_required,
    tower_sessions::{MemoryStore, SessionManagerLayer},
    AuthManagerLayerBuilder,
    AuthUser,
    AuthnBackend,
    UserId,
};

use serde::Deserialize;

// ----------------------
// USER
// ----------------------

#[derive(Debug, Clone)]
struct User {
    id: i64,
    pw_hash: Vec<u8>,
}

impl AuthUser for User {
    type Id = i64;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn session_auth_hash(&self) -> &[u8] {
        &self.pw_hash
    }
}

// ----------------------
// BACKEND
// ----------------------

#[derive(Clone, Default)]
struct Backend {
    users: HashMap<i64, User>,
}

// ----------------------
// CREDENTIALS
// ----------------------

#[derive(Clone, Deserialize)]
struct Credentials {
    user_id: i64,
}

// ----------------------
// AUTHENTICATION BACKEND
// ----------------------

impl AuthnBackend for Backend {
    type User = User;
    type Credentials = Credentials;
    type Error = Infallible;

    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        Ok(self.users.get(&creds.user_id).cloned())
    }

    async fn get_user(
        &self,
        user_id: &UserId<Self>,
    ) -> Result<Option<Self::User>, Self::Error> {
        Ok(self.users.get(user_id).cloned())
    }
}

type AuthSession = axum_login::AuthSession<Backend>;

// ----------------------
// LOGIN PAGE
// ----------------------

async fn login_page() -> Html<&'static str> {
    Html(
        r#"
        <html>
            <body>
                <h1>Login</h1>
                <form action="/login" method="post">
                    <input
                        type="number"
                        name="user_id"
                        placeholder="User ID"
                        required
                    />
                    <button type="submit">Login</button>
                </form>
            </body>
        </html>
        "#,
    )
}

// ----------------------
// LOGIN HANDLER
// ----------------------

async fn login(
    mut auth_session: AuthSession,
    Form(creds): Form<Credentials>,
) -> impl IntoResponse {
    let user = match auth_session.authenticate(creds).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        Err(_) => {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if auth_session.login(&user).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    Redirect::to("/protected").into_response()
}

// ----------------------
// PROTECTED ROUTE
// ----------------------

async fn protected() -> &'static str {
    "Gotta be logged in to see me!"
}

async fn protected2() -> &'static str {
    "another protected route"
}

// ----------------------
// MAIN
// ----------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Demo user
    let mut users = HashMap::new();

    users.insert(
        1,
        User {
            id: 1,
            pw_hash: b"demo-session-hash".to_vec(),
        },
    );

    let backend = Backend { users };

    // Session storage
    let session_store = MemoryStore::default();

    // HTTP only for local development
    let session_layer =
        SessionManagerLayer::new(session_store)
            .with_secure(false);

    // Authentication middleware
    let auth_layer =
        AuthManagerLayerBuilder::new(backend, session_layer)
            .build();

    // Router
    let app = Router::new()
        .route("/protected", get(protected))
        .route("/protected2", get(protected2))
        .route_layer(
            login_required!(Backend, login_url = "/login")
        )
        .route("/login", get(login_page).post(login))
        .layer(auth_layer);

    let listener =
        tokio::net::TcpListener::bind("127.0.0.1:3000").await?;

    println!("Server running at http://127.0.0.1:3000");

    axum::serve(listener, app).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_backend() -> Backend {
        let mut users = HashMap::new();

        users.insert(
            1,
            User {
                id: 1,
                pw_hash: b"test-hash".to_vec(),
            },
        );

        Backend { users }
    }

    #[tokio::test]
    async fn test_login_success() {
        let backend = test_backend();

        let credentials = Credentials { user_id: 1 };

        let result = backend.authenticate(credentials).await.unwrap();

        assert!(result.is_some());
        assert_eq!(result.unwrap().id, 1);
    }

    #[tokio::test]
    async fn test_login_invalid_user() {
        let backend = test_backend();

        let credentials = Credentials { user_id: 999 };

        let result = backend.authenticate(credentials).await.unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_get_user() {
        let backend = test_backend();

        let result = backend.get_user(&1).await.unwrap();

        assert!(result.is_some());

        let user = result.unwrap();

        assert_eq!(user.id, 1);
        assert_eq!(user.session_auth_hash(), b"test-hash");
    }

    #[tokio::test]
    async fn test_login_page() {
        let response = login_page().await;

        assert!(response.0.contains("<form"));
        assert!(response.0.contains("user_id"));
    }

    use axum::{
        body::{to_bytes, Body},
        http::{header, Method, Request, StatusCode},
    };

    use tower::ServiceExt;

    // Build a Router specifically for testing
    fn test_app() -> Router {
        let mut users = HashMap::new();

        users.insert(
            1,
            User {
                id: 1,
                pw_hash: b"test-hash".to_vec(),
            },
        );

        let backend = Backend { users };

        let session_store = MemoryStore::default();

        let session_layer =
            SessionManagerLayer::new(session_store)
                .with_secure(false);

        let auth_layer =
            AuthManagerLayerBuilder::new(backend, session_layer)
                .build();

        Router::new()
            .route("/protected", get(protected))
            .route_layer(
                login_required!(Backend, login_url = "/login")
            )
            .route("/login", get(login_page).post(login))
            .layer(auth_layer)
    }

    // --------------------------
    // TEST 1: GET /login
    // --------------------------

    #[tokio::test]
    async fn test_login_page_routes() {
        let app = test_app();

        let request = Request::builder()
            .method(Method::GET)
            .uri("/login")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();

        let html = String::from_utf8(body.to_vec()).unwrap();

        assert!(html.contains("<form"));
        assert!(html.contains("user_id"));
    }

    // --------------------------
    // TEST 2: PROTECTED WITHOUT LOGIN
    // --------------------------

    #[tokio::test]
    async fn test_protected_without_login_routes() {
        let app = test_app();

        let request = Request::builder()
            .method(Method::GET)
            .uri("/protected")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert!(response.status().is_redirection());

        let location = response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();

        assert!(location.starts_with("/login"));
    }

    // --------------------------
    // TEST 3: INVALID LOGIN
    // --------------------------

    #[tokio::test]
    async fn test_invalid_login_routes() {
        let app = test_app();

        let request = Request::builder()
            .method(Method::POST)
            .uri("/login")
            .header(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Body::from("user_id=999"))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED
        );
    }

    // --------------------------
    // TEST 4: LOGIN + ACCESS PROTECTED
    // --------------------------

    #[tokio::test]
    async fn test_login_and_access_protected_routes() {
        let app = test_app();

        // Step 1: Login
        let login_request = Request::builder()
            .method(Method::POST)
            .uri("/login")
            .header(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Body::from("user_id=1"))
            .unwrap();

        let login_response = app
            .clone()
            .oneshot(login_request)
            .await
            .unwrap();

        assert_eq!(
            login_response.status(),
            StatusCode::SEE_OTHER
        );

        // Step 2: Extract session cookie
        let cookie = login_response
            .headers()
            .get(header::SET_COOKIE)
            .expect("Missing session cookie")
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();

        // Step 3: Access protected route
        let protected_request = Request::builder()
            .method(Method::GET)
            .uri("/protected")
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap();

        let response = app
            .oneshot(protected_request)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Step 4: Verify response body
        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();

        let text = String::from_utf8(body.to_vec()).unwrap();

        assert_eq!(
            text,
            "Gotta be logged in to see me!"
        );
    }
}