use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// A generic error occurred while processing code signature")]
    #[error("Code signing error happened: {0}")]
    Generic(&'static str),

    /// Searched in all available catalog files and the requested hash was not found
    #[error("Exhausted catalog search")]
    ExhaustedCatalogs,

    /// Opening the file failed
    #[error("Failed to open file")]
    OpenFileFailed,

    /// Could not hash the target file
    #[error("Could not obtain file hash for {0}")]
    UnableToHash(String),

    /// Unable to convert a wide string
    #[error("Could not convert string: {0}")]
    WideStringConversion(#[source] widestring::error::MissingNulTerminator),

    /// Unable to get certificate store context
    #[error("Unable to obtain certificate store context")]
    AdminContext,

    /// Unspecified error has occured
    #[error("An unspecified error has occured")]
    Unspecified,
}
