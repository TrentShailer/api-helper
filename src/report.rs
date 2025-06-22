use core::{fmt::Display, panic::Location};

use crate::ErrorResponse;

#[track_caller]
pub fn report_error<E: Display>(error: E) {
    tracing::error!("[{}] INTERNAL SERVER ERROR: {error}", Location::caller())
}

pub trait InternalServerError<T> {
    #[track_caller]
    fn internal_server_error(self) -> Result<T, ErrorResponse>;

    #[track_caller]
    fn internal_server_error_context<C: Display>(self, context: C) -> Result<T, ErrorResponse>;
}

impl<T, E: Display> InternalServerError<T> for Result<T, E> {
    #[track_caller]
    fn internal_server_error(self) -> Result<T, ErrorResponse> {
        self.map_err(|error| {
            report_error(error);
            ErrorResponse::internal_server_error()
        })
    }

    #[track_caller]
    fn internal_server_error_context<C: Display>(self, context: C) -> Result<T, ErrorResponse> {
        self.map_err(|error| {
            report_error(format!("{context}: {error}"));
            ErrorResponse::internal_server_error()
        })
    }
}

impl<T> InternalServerError<T> for Option<T> {
    #[track_caller]
    fn internal_server_error(self) -> Result<T, ErrorResponse> {
        self.ok_or_else(|| {
            report_error("Option was None");
            ErrorResponse::internal_server_error()
        })
    }

    #[track_caller]
    fn internal_server_error_context<C: Display>(self, context: C) -> Result<T, ErrorResponse> {
        self.ok_or_else(|| {
            report_error(format!("Option (`{context}`) was None"));
            ErrorResponse::internal_server_error()
        })
    }
}
