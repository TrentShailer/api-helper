use axum::{
    extract::{FromRequest, OptionalFromRequest, Request},
    response::IntoResponse,
};
use serde::{Serialize, de::DeserializeOwned};

use crate::ErrorResponse;

/// Custom JSON extractor for returning [`crate::ErrorResponse`] errors.
pub struct Json<T>(pub T);

impl<T: Serialize> IntoResponse for Json<T> {
    fn into_response(self) -> axum::response::Response {
        let Self(value) = self;
        axum::Json(value).into_response()
    }
}

impl<T, S> FromRequest<S> for Json<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ErrorResponse;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        <axum::Json<_> as FromRequest<S>>::from_request(req, state)
            .await
            .map_err(ErrorResponse::from)
            .map(|value| Self(value.0))
    }
}

impl<T, S> OptionalFromRequest<S> for Json<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ErrorResponse;

    async fn from_request(req: Request, state: &S) -> Result<Option<Self>, Self::Rejection> {
        <axum::Json<_> as OptionalFromRequest<S>>::from_request(req, state)
            .await
            .map_err(ErrorResponse::from)
            .map(|value| value.map(|value| Self(value.0)))
    }
}
