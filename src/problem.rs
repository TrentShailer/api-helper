use core::{error::Error, panic::Location};

use axum::{extract::rejection::JsonRejection, response::IntoResponse};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use ts_rust_helper::error::{ErrorLogger, IntoErrorReport};

/// Trait for providing convenience functions to mark an error as an internal server error.
pub trait InternalServerError<T> {
    /// Mark the error as an internal server error.
    #[track_caller]
    fn internal_server_error(self) -> Result<T, ErrorResponse>;
}

impl<T, E: Error> InternalServerError<T> for Result<T, E> {
    #[track_caller]
    fn internal_server_error(self) -> Result<T, ErrorResponse> {
        self.into_report()
            .log_error()
            .map_err(|_| ErrorResponse::internal_server_error())
    }
}

impl<T> InternalServerError<T> for Option<T> {
    #[track_caller]
    fn internal_server_error(self) -> Result<T, ErrorResponse> {
        self.into_report()
            .log_error()
            .map_err(|_| ErrorResponse::internal_server_error())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// A problem detailing part of the error response.
pub struct Problem {
    /// A JSON path that identifies the part of the request that was the cause of the problem.
    pub pointer: String,
    /// A human-readable explanation specific to this occurrence of the problem.
    pub detail: String,
}
impl Problem {
    /// Create a new problem from a pointer and some details.
    pub fn new<S1: ToString, S2: ToString>(pointer: S1, detail: S2) -> Self {
        Self {
            pointer: pointer.to_string(),
            detail: detail.to_string(),
        }
    }
}

/// JSON payload for an error response.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    #[serde(skip)]
    /// Status code of the response
    pub status: StatusCode,
    /// The list of problems to relay to the caller.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub problems: Vec<Problem>,
}

impl ErrorResponse {
    /// Convenience function for an internal server error response.
    pub fn internal_server_error() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            problems: vec![],
        }
    }

    /// Convenience function for an unauthenticated response.
    #[track_caller]
    pub fn unauthenticated() -> Self {
        log::warn!("[{}] request was unauthenticated", Location::caller());
        Self {
            status: StatusCode::UNAUTHORIZED,
            problems: vec![],
        }
    }

    /// Convenience function for a bad request response, with a set of problems that made the client
    /// should fix.
    pub fn bad_request(problems: Vec<Problem>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            problems,
        }
    }

    /// Convenience function for an unprocessable entity response.
    #[track_caller]
    pub fn unprocessable_entity() -> Self {
        log::warn!("[{}] request was unprocessable", Location::caller());
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            problems: vec![],
        }
    }

    /// Convenience function for a forbidden response.
    pub fn forbidden() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            problems: vec![],
        }
    }
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> axum::response::Response {
        if self.problems.is_empty() {
            self.status.into_response()
        } else {
            (self.status, axum::Json(&self)).into_response()
        }
    }
}

impl From<JsonRejection> for ErrorResponse {
    fn from(value: JsonRejection) -> Self {
        log::warn!(
            "request contained an unprocessable body ({}): {}",
            value.status(),
            value.body_text()
        );
        Self::unprocessable_entity()
    }
}
