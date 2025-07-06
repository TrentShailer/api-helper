use core::error::Error;

use axum::{extract::rejection::JsonRejection, response::IntoResponse};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use ts_rust_helper::error::{ErrorLogger, IntoErrorReport};

/// Trait for providing convenience functions to mark an error as an internal server error.
pub trait InternalServerError<T> {
    /// Mark the error as an internal server error.
    fn internal_server_error<S: ToString>(self, context: S) -> Result<T, ErrorResponse>;
}

impl<T, E: Error> InternalServerError<T> for Result<T, E> {
    fn internal_server_error<S: ToString>(self, context: S) -> Result<T, ErrorResponse> {
        self.into_report(context)
            .log_error()
            .map_err(|_| ErrorResponse::internal_server_error())
    }
}

impl<T> InternalServerError<T> for Option<T> {
    fn internal_server_error<S: ToString>(self, context: S) -> Result<T, ErrorResponse> {
        self.into_report(context)
            .log_error()
            .map_err(|_| ErrorResponse::internal_server_error())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// A problem detailing part of the error response.
pub struct Problem {
    /// A JSON path that identifies the part of the request that was the cause of the problem.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pointer: Option<String>,
    /// A human-readable explanation specific to this occurrence of the problem.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}
impl Problem {
    /// Create a new problem from a pointer and some details.
    pub fn new<S1: ToString, S2: ToString>(pointer: S1, detail: S2) -> Self {
        Self {
            pointer: Some(pointer.to_string()),
            detail: Some(detail.to_string()),
        }
    }

    /// Create a new problem with just a pointer.
    pub fn pointer<S: ToString>(pointer: S) -> Self {
        Self {
            pointer: Some(pointer.to_string()),
            detail: None,
        }
    }

    /// Create a new problem with just the details.
    pub fn detail<S: ToString>(detail: S) -> Self {
        Self {
            pointer: None,
            detail: Some(detail.to_string()),
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
    pub fn unauthenticated() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            problems: vec![Problem::detail("This request requires authentication")],
        }
    }

    /// Convenience function for a not found response, with an optional pointer to what was not found.
    pub fn not_found<S: ToString>(pointer: Option<S>) -> Self {
        let problems = match pointer {
            Some(pointer) => vec![Problem::pointer(pointer)],
            None => vec![],
        };
        Self {
            status: StatusCode::NOT_FOUND,
            problems,
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
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> axum::response::Response {
        (self.status, axum::Json(&self)).into_response()
    }
}

impl From<JsonRejection> for ErrorResponse {
    fn from(value: JsonRejection) -> Self {
        match value {
            JsonRejection::JsonDataError(json_data_error) => Self {
                status: json_data_error.status(),
                problems: vec![Problem::detail(json_data_error.body_text())],
            },

            JsonRejection::JsonSyntaxError(json_syntax_error) => Self {
                status: json_syntax_error.status(),
                problems: vec![Problem::detail(json_syntax_error.body_text())],
            },

            JsonRejection::MissingJsonContentType(missing_json_content_type) => Self {
                status: missing_json_content_type.status(),
                problems: vec![Problem::detail(missing_json_content_type.body_text())],
            },

            JsonRejection::BytesRejection(bytes_rejection) => Self {
                status: bytes_rejection.status(),
                problems: vec![Problem::detail(bytes_rejection.body_text())],
            },

            rejection => Self {
                status: rejection.status(),
                problems: vec![Problem::detail(rejection.body_text())],
            },
        }
    }
}
