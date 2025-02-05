use std::path::PathBuf;
use std::str::Utf8Error;
use thiserror::Error;
use sysmon_validator::{ValidationError, errors::ParserError};

#[derive(Error, Debug)]
pub enum PreprocessError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("XML parsing error: {0}")]
    XmlError(#[from] quick_xml::Error),

    #[error("Validation error: {0}")]
    ValidationError(#[from] ValidationError),

    #[error("Path error: {0}")]
    PathError(String),

    #[error("Parser error: {0}")]
    ParserError(#[from] ParserError),
}

#[derive(Error, Debug)]
pub enum ConversionError {

    #[error("IO error at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("XML parsing error: {0}")]
    XmlParse(#[from] quick_xml::DeError),

    #[error("JSON parsing error: {0}")]
    JsonParse(#[from] serde_json::Error),

    #[error("Invalid file: {0}")]
    InvalidFile(String),
    
    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Parser error: {0}")]
    ParserError(String),

    #[error("Batch conversion errors:\n{0}")]
    BatchConversionError(String),

    #[error("Batch processing error: {0}")]
    BatchError(String),

    #[error("File size exceeds limit: {path} ({size} bytes)")]
    FileSizeLimitExceeded {
        path: String,
        size: u64,
    },

    #[error("Max depth exceeded: {path} (max: {depth})")]
    MaxDepthExceeded {
        path: String,
        depth: u32,
    },

    #[error("Verification failed: {0}")]
    VerificationError(String),

    #[error("Preprocessing error: {0}")]
    PreprocessError(PreprocessError),
}

impl From<ValidationError> for ConversionError {
    fn from(err: ValidationError) -> Self {
        ConversionError::ValidationError(err.to_string())
    }
}

impl From<ParserError> for ConversionError {
    fn from(err: ParserError) -> Self {
        ConversionError::ParserError(err.to_string())
    }
}

impl From<PreprocessError> for ConversionError {
    fn from(err: PreprocessError) -> Self {
        ConversionError::PreprocessError(err)
    }
}

impl From<Utf8Error> for PreprocessError {
    fn from(err: Utf8Error) -> Self {
        PreprocessError::PathError(format!("Invalid UTF-8: {}", err))
    }
}

impl ConversionError {
    pub fn io_error(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        ConversionError::Io {
            path: path.into(),
            source,
        }
    }
}

impl From<quick_xml::events::attributes::AttrError> for PreprocessError {
    fn from(err: quick_xml::events::attributes::AttrError) -> Self {
        PreprocessError::XmlError(quick_xml::Error::from(err))
    }
}

impl From<std::io::Error> for ConversionError {
    fn from(source: std::io::Error) -> Self {
        ConversionError::Io {
            path: PathBuf::from("<unknown>"),
            source,
        }
    }
}