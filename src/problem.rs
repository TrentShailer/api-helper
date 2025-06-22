use axum::{extract::rejection::JsonRejection, response::IntoResponse};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// A problem detailing part of the error response.
pub struct Problem {
    /// A JSON path that identifies the part of the request that was the cause of the problem.
    pub pointer: Option<String>,
    /// A human-readable explanation specific to this occurrence of the problem.
    pub detail: Option<String>,
}
impl Problem {
    pub fn new<S1: ToString, S2: ToString>(pointer: S1, detail: S2) -> Self {
        Self {
            pointer: Some(pointer.to_string()),
            detail: Some(detail.to_string()),
        }
    }

    pub fn pointer<S: ToString>(pointer: S) -> Self {
        Self {
            pointer: Some(pointer.to_string()),
            detail: None,
        }
    }

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
    pub fn internal_server_error() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            problems: vec![],
        }
    }

    pub fn unauthenticated() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            problems: vec![Problem::detail("This request requires authentication")],
        }
    }

    pub fn not_found(pointer: Option<String>) -> Self {
        let problems = match pointer {
            Some(pointer) => vec![Problem::pointer(pointer)],
            None => vec![],
        };
        Self {
            status: StatusCode::NOT_FOUND,
            problems,
        }
    }

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
