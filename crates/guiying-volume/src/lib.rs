//! Read-only volume binding and lossless relative-path semantics for Guiying.
//!
//! This crate deliberately exposes no API for creating, renaming, timestamping,
//! or removing filesystem objects. A [`BoundVolumeSession`] owns a directory
//! descriptor for the selected root, binds observations to an independently
//! generated mount-session key, and revalidates both the descriptor and its
//! original path before a relative file is opened.
//!
//! macOS is the only volume-observation backend currently implemented. Other
//! platforms fail closed with [`VolumeError::UnsupportedPlatform`]; path
//! validation remains platform-independent so persisted paths can be checked
//! before they reach a platform backend.

#![deny(unsafe_code)]

mod error;
mod model;
mod path;
mod platform;
mod profile;
mod volume;

pub use error::{PathError, VolumeError};
pub use model::{
    FileObjectIdentity, IdentityStrength, KeyDigest, MountObservation, NativePathEncoding,
    NativeUuid, NativeValue, ReadOnlyFormatCapabilities, RootObjectIdentity, SpaceObservation,
    VolumeIdentity, VolumeObservation, WriteCapabilities,
};
pub use path::{
    LosslessRelativePath, SerializedRelativePath, MAX_COMPONENT_BYTES, MAX_DISPLAY_PATH_BYTES,
    MAX_PATH_COMPONENTS, MAX_RELATIVE_PATH_BYTES,
};
pub use profile::{
    KeyStrategy, PathSemanticsProfile, ProfileOrigin, UnicodeNormalizationObservation,
    PATH_KEY_ALGORITHM_VERSION, PATH_SEMANTICS_PROFILE_VERSION,
};
pub use volume::{BoundVolumeSession, ReadOnlyFile, MAX_ROOT_PATH_BYTES};
