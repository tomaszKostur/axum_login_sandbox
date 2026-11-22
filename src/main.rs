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
}