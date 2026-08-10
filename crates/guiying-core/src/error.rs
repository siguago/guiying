use std::io;
use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("at least one scan root is required")]
    NoRoots,
    #[error("invalid scan option: {0}")]
    InvalidOption(String),
    #[error("cannot inspect scan root {path}: {source}")]
    RootMetadata {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("scan root is a symbolic link and will not be followed: {0}")]
    RootIsSymlink(PathBuf),
    #[error("scan root is neither a regular file nor a directory: {0}")]
    UnsupportedRoot(PathBuf),
    #[error("scan root is excluded by the safety policy: {path} ({reason})")]
    ExcludedRoot { path: PathBuf, reason: String },
}

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("verification was cancelled")]
    Cancelled,
    #[error("cannot inspect {path}: {source}")]
    Metadata {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("refusing to read non-regular file: {0}")]
    NotRegularFile(PathBuf),
    #[error("file changed while it was being verified: {0}")]
    ChangedDuringRead(PathBuf),
    #[error("cannot open {path}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

impl VerificationError {
    pub(crate) fn path(&self) -> Option<&std::path::Path> {
        match self {
            Self::Metadata { path, .. }
            | Self::Open { path, .. }
            | Self::Read { path, .. }
            | Self::NotRegularFile(path)
            | Self::ChangedDuringRead(path) => Some(path),
            Self::Cancelled => None,
        }
    }
}

#[derive(Debug, Error)]
pub enum PathRefDecodeError {
    #[error("path payload is not valid base64: {0}")]
    InvalidBase64(String),
    #[error("path encoding {0} is not supported on this platform")]
    UnsupportedEncoding(&'static str),
    #[error("UTF-16 path payload has an odd byte length")]
    InvalidUtf16Length,
    #[error("UTF-8 path payload is invalid: {0}")]
    InvalidUtf8(String),
}
