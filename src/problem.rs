use axum::{extract::rejection::JsonRejection, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// A problem detailing part of the error response.
pub struct Problem {
    /// A kebab case string that identifies the problem type.
    pub code: String,

    /// A short, human-readable summary of the problem type.
    pub title: String,

    /// A human-readable explanation specific to this occurrence of the problem.
    pub detail: Option<String>,

    /// A JSON path that identifies the part of the request that was the cause of the problem.
    pub pointer: Option<String>,
}

impl Problem {
    pub fn invalid_field<S1: ToString, S2: ToString>(detail: S1, pointer: S2) -> Self {
        Self {
            code: String::from("invalid-field"),
            title: String::from("Your request contained invalid fields."),
            detail: Some(detail.to_string()),
            pointer: Some(pointer.to_string()),
        }
    }

    pub fn server_error() -> Self {
        Self {
            code: String::from("server-error"),
            title: String::from(
                "The server encountered an unexpected error while processing your request.",
            ),
            detail: None,
            pointer: None,
        }
    }

    pub fn not_found() -> Self {
        Self {
            code: String::from("not-found"),
            title: String::from("The resource was not found."),
            detail: None,
            pointer: None,
        }
    }

    pub fn new<S1: ToString, S2: ToString>(code: S1, title: S2) -> Self {
        Self {
            code: code.to_string(),
            title: title.to_string(),
            detail: None,
            pointer: None,
        }
    }

    pub fn detail<S: ToString>(mut self, value: S) -> Self {
        self.detail = Some(value.to_string());
        self
    }

    pub fn pointer<S: ToString>(mut self, value: S) -> Self {
        self.pointer = Some(value.to_string());
        self
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
    pub fn new(status: StatusCode, problems: Vec<Problem>) -> Self {
        Self { status, problems }
    }

    pub fn single(status: StatusCode, problem: Problem) -> Self {
        Self {
            status,
            problems: vec![problem],
        }
    }

    pub fn server_error() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            problems: vec![Problem::server_error()],
        }
    }

    pub fn unuathenticated() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            problems: vec![Problem::new(
                "unauthenticated",
                "This request requires authentication",
            )],
        }
    }

    pub fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            problems: vec![Problem::not_found()],
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
                problems: vec![Problem::new(
                    "invalid-body-data",
                    json_data_error.body_text(),
                )],
            },

            JsonRejection::JsonSyntaxError(json_syntax_error) => Self {
                status: json_syntax_error.status(),
                problems: vec![Problem::new(
                    "invalid-body-syntax",
                    json_syntax_error.body_text(),
                )],
            },

            JsonRejection::MissingJsonContentType(missing_json_content_type) => Self {
                status: missing_json_content_type.status(),
                problems: vec![Problem::new(
                    "invalid-content-type",
                    missing_json_content_type.body_text(),
                )],
            },

            JsonRejection::BytesRejection(bytes_rejection) => Self {
                status: bytes_rejection.status(),
                problems: vec![Problem::new(
                    "invalid-body-bytes",
                    bytes_rejection.body_text(),
                )],
            },

            rejection => Self {
                status: rejection.status(),
                problems: vec![Problem::new("invalid-body", rejection.body_text())],
            },
        }
    }
}
