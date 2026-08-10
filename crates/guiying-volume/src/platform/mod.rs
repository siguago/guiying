#[cfg(not(target_os = "macos"))]
use std::fs::File;
#[cfg(not(target_os = "macos"))]
use std::path::Path;

#[cfg(not(target_os = "macos"))]
use crate::{FileObjectIdentity, VolumeError};
use crate::{MountObservation, NativeUuid, ReadOnlyFormatCapabilities, RootObjectIdentity};

pub(crate) struct BindParts {
    pub root_identity: RootObjectIdentity,
    pub mount: MountObservation,
    pub mount_source_raw: Vec<u8>,
    pub filesystem_type_raw: Vec<u8>,
    pub native_uuid: Option<NativeUuid>,
    pub format_capabilities: ReadOnlyFormatCapabilities,
}

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub(crate) use macos::{bind, open_regular_file, revalidate, snapshot_file, PlatformSession};

#[cfg(not(target_os = "macos"))]
pub(crate) struct PlatformSession;

#[cfg(not(target_os = "macos"))]
pub(crate) fn bind(_root: &Path) -> Result<(PlatformSession, BindParts), VolumeError> {
    Err(VolumeError::UnsupportedPlatform {
        platform: std::env::consts::OS,
    })
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn revalidate(_session: &PlatformSession) -> Result<(), VolumeError> {
    Err(VolumeError::UnsupportedPlatform {
        platform: std::env::consts::OS,
    })
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn open_regular_file(
    _session: &PlatformSession,
    _components: &[&[u8]],
) -> Result<(File, FileObjectIdentity), VolumeError> {
    Err(VolumeError::UnsupportedPlatform {
        platform: std::env::consts::OS,
    })
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn snapshot_file(_file: &File) -> Result<FileObjectIdentity, VolumeError> {
    Err(VolumeError::UnsupportedPlatform {
        platform: std::env::consts::OS,
    })
}
