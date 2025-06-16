use core::{fmt::Display, panic::Location};

#[track_caller]
pub fn report_error<E: Display>(error: E, message: &str) {
    tracing::error!("{message} [{}]: {error}", Location::caller())
}

pub trait ReportUnexpected {
    #[track_caller]
    fn report_error(self, message: &str) -> Self;
}

impl<T, E: Display> ReportUnexpected for Result<T, E> {
    #[track_caller]
    fn report_error(self, message: &str) -> Self {
        if let Err(error) = self.as_ref() {
            report_error(error, message);
        }

        self
    }
}

impl<T> ReportUnexpected for Option<T> {
    #[track_caller]
    fn report_error(self, message: &str) -> Self {
        if self.is_none() {
            report_error("was None", message);
        }

        self
    }
}
