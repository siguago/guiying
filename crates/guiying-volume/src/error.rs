use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PathError {
    #[error("path encoding does not match the semantics profile")]
    EncodingProfileMismatch,
    #[error("path belongs to a different semantics profile")]
    ProfileMismatch,
    #[error("relative path exceeds the hard limit of {limit} bytes")]
    PathTooLong { limit: usize },
    #[error("relative path has more than the hard limit of {limit} components")]
    TooManyComponents { limit: usize },
    #[error("path component {index} exceeds the hard limit of {limit} bytes")]
    ComponentTooLong { index: usize, limit: usize },
    #[error("relative path is absolute or rooted")]
    AbsolutePath,
    #[error("relative path contains a NUL value")]
    Nul,
    #[error("relative path contains an empty component at index {index}")]
    EmptyComponent { index: usize },
    #[error("relative path contains a dot component at index {index}")]
    DotComponent { index: usize },
    #[error("relative path contains a parent component at index {index}")]
    ParentComponent { index: usize },
    #[error("UTF-16LE path bytes have an odd length")]
    InvalidUtf16Length,
    #[error("Windows path contains an alternate-data-stream or drive separator")]
    WindowsAdsOrDrive,
    #[error("Windows path contains a forbidden character in component {index}")]
    WindowsForbiddenCharacter { index: usize },
    #[error("Windows path contains a reserved device component at index {index}")]
    WindowsReservedDevice { index: usize },
    #[error("Windows path contains an ambiguous trailing space or dot at component {index}")]
    WindowsAmbiguousTrailingCharacter { index: usize },
    #[error("serialized raw path is not canonical unpadded base64: {0}")]
    InvalidBase64(String),
    #[error("serialized display text does not match the lossless raw path")]
    DisplayMismatch,
    #[error("serialized display text exceeds the hard limit of {limit} UTF-8 bytes")]
    DisplayTooLong { limit: usize },
    #[error("serialized path key does not match its raw path and profile")]
    PathKeyMismatch,
    #[error("the volume root cannot be opened as a regular relative file")]
    RootIsNotAFile,
    #[error("path encoding is unsupported on this operating system")]
    UnsupportedEncoding,
}

#[derive(Debug, Error)]
pub enum VolumeError {
    #[error("volume observation is unsupported on platform {platform}")]
    UnsupportedPlatform { platform: &'static str },
    #[error("the selected root must be an absolute path")]
    RootNotAbsolute,
    #[error("the selected root contains a NUL byte")]
    RootContainsNul,
    #[error("the selected root exceeds the hard limit of {limit} bytes")]
    RootPathTooLong { limit: usize },
    #[error("the selected root contains an empty or trailing component")]
    RootHasEmptyComponent,
    #[error("the selected root contains '.' or '..' components")]
    UnsafeRootComponent,
    #[error("the selected root's final component is a symbolic link")]
    RootSymlink,
    #[error("the selected root is not a directory")]
    RootNotDirectory,
    #[error("the selected root identity changed while it was being bound")]
    RootChangedDuringBind,
    #[error("the bound root no longer resolves to the original directory")]
    RootBindingChanged,
    #[error("the mounted filesystem changed during the bound session")]
    MountSessionChanged,
    #[error("the volume returned malformed system metadata for {field}")]
    MalformedSystemMetadata { field: &'static str },
    #[error("the operating system could not provide a mount-session nonce: {0}")]
    Entropy(String),
    #[error("relative path is unsafe: {0}")]
    Path(#[from] PathError),
    #[error("relative component {component_index} could not be opened safely: {source}")]
    UnsafePathResolution {
        component_index: usize,
        #[source]
        source: io::Error,
    },
    #[error("relative path crossed a mount boundary")]
    CrossedMountBoundary,
    #[error("relative target is not a regular file")]
    NotRegularFile,
    #[error("the relative file identity changed while it was being opened")]
    FileChangedDuringOpen,
    #[error("the opened file belongs to a different bound mount session")]
    FileSessionMismatch,
    #[error("the opened file was resolved from a different relative path")]
    FilePathMismatch,
    #[error("I/O failure while {operation}: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
}

impl VolumeError {
    #[cfg(target_os = "macos")]
    pub(crate) fn io(operation: &'static str, source: impl Into<io::Error>) -> Self {
        Self::Io {
            operation,
            source: source.into(),
        }
    }
}
