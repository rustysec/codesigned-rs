use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// A generic error occurred while processing code signature")]
    #[error("Code signing error happened")]
    Generic,

    /// Searched in all available catalog files and the requested hash was not found
    #[error("Exhausted catalog search")]
    ExhaustedCatalogs,

    /// Opening the file failed
    #[error("Failed to open file")]
    OpenFileFailed,
}
