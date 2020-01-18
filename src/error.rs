use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// A generic error occurred while processing code signature")]
    #[error("Code signing error happened")]
    Generic,
}
