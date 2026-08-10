use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use blake3::Hasher;

use crate::model::{IdentityStrength, KeyDigest, NativePathEncoding, VolumeIdentity};
use crate::platform::{self, PlatformSession};
use crate::{
    FileObjectIdentity, LosslessRelativePath, PathError, PathSemanticsProfile, VolumeError,
    VolumeObservation,
};

pub const MAX_ROOT_PATH_BYTES: usize = 64 * 1024;

pub struct BoundVolumeSession {
    inner: PlatformSession,
    observation: VolumeObservation,
}

impl BoundVolumeSession {
    /// Bind an absolute directory root without following its final symlink.
    ///
    /// On macOS, all volume metadata is collected from the opened descriptor.
    /// Linux and Windows currently return `UnsupportedPlatform` rather than
    /// falling back to path names, shell commands, or guessed filesystem rules.
    pub fn bind(root: impl AsRef<Path>) -> Result<Self, VolumeError> {
        let (inner, parts) = platform::bind(root.as_ref())?;
        let identity = make_volume_identity(
            parts.native_uuid,
            &parts.mount_source_raw,
            &parts.filesystem_type_raw,
            parts.root_identity.device,
        );
        let mount_session_key = make_mount_session_key(
            identity.key(),
            &parts.mount_source_raw,
            &parts.filesystem_type_raw,
            parts.root_identity,
            parts.mount.raw_flags(),
        )?;
        let path_semantics = PathSemanticsProfile::from_mount_observation(
            identity.key(),
            mount_session_key,
            NativePathEncoding::UnixBytes,
            parts.format_capabilities,
        );
        let observation = VolumeObservation::new(
            identity,
            mount_session_key,
            parts.mount,
            parts.root_identity,
            parts.format_capabilities,
            path_semantics,
        );
        Ok(Self { inner, observation })
    }

    pub const fn observation(&self) -> &VolumeObservation {
        &self.observation
    }

    pub const fn path_semantics(&self) -> &PathSemanticsProfile {
        self.observation.path_semantics()
    }

    /// Recheck descriptor identity, mount metadata, native UUID, and the
    /// original selected path. Any mismatch invalidates the current session.
    pub fn revalidate(&self) -> Result<(), VolumeError> {
        platform::revalidate(&self.inner)
    }

    /// Open a regular file component-by-component from the bound root.
    ///
    /// Every ancestor and the final component use no-follow semantics. A
    /// nested mount is rejected by device identity. The mount session is
    /// revalidated both before and after the open.
    pub fn open_regular_file(
        &self,
        path: &LosslessRelativePath,
    ) -> Result<ReadOnlyFile, VolumeError> {
        if path.profile_key() != self.path_semantics().profile_key() {
            return Err(PathError::ProfileMismatch.into());
        }
        if path.is_root() {
            return Err(PathError::RootIsNotAFile.into());
        }
        let components: Vec<&[u8]> = path.unix_components()?.collect();
        let (file, identity) = platform::open_regular_file(&self.inner, &components)?;
        Ok(ReadOnlyFile {
            file,
            initial_identity: identity,
            mount_session_key: self.observation.mount_session_key(),
            path_key: path.path_key(),
        })
    }
}

pub struct ReadOnlyFile {
    file: File,
    initial_identity: FileObjectIdentity,
    mount_session_key: KeyDigest,
    path_key: KeyDigest,
}

impl ReadOnlyFile {
    pub const fn initial_identity(&self) -> FileObjectIdentity {
        self.initial_identity
    }

    /// Verify the descriptor, its original lossless path, and the bound mount
    /// session after the caller finishes reading.
    ///
    /// This intentionally reopens the same relative path with component-wise
    /// no-follow resolution. It detects both in-place mutation and replacing
    /// the directory entry while the original descriptor remained readable.
    pub fn verify_unchanged(
        &self,
        session: &BoundVolumeSession,
        path: &LosslessRelativePath,
    ) -> Result<bool, VolumeError> {
        if self.mount_session_key != session.observation.mount_session_key() {
            return Err(VolumeError::FileSessionMismatch);
        }
        if self.path_key != path.path_key() {
            return Err(VolumeError::FilePathMismatch);
        }
        if path.profile_key() != session.path_semantics().profile_key() {
            return Err(PathError::ProfileMismatch.into());
        }

        session.revalidate()?;
        let descriptor_before = platform::snapshot_file(&self.file)?;
        if descriptor_before != self.initial_identity {
            return Ok(false);
        }
        let components: Vec<&[u8]> = path.unix_components()?.collect();
        let (reopened, reopened_identity) =
            platform::open_regular_file(&session.inner, &components)?;
        let reopened_after = platform::snapshot_file(&reopened)?;
        let descriptor_after = platform::snapshot_file(&self.file)?;
        session.revalidate()?;
        Ok(reopened_identity == self.initial_identity
            && reopened_after == self.initial_identity
            && descriptor_after == self.initial_identity)
    }

    /// Check only the already-open descriptor. For a complete stable-input
    /// check, use [`ReadOnlyFile::verify_unchanged`].
    pub fn verify_descriptor_unchanged(&self) -> Result<bool, VolumeError> {
        Ok(platform::snapshot_file(&self.file)? == self.initial_identity)
    }
}

impl Read for ReadOnlyFile {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buffer)
    }
}

impl Seek for ReadOnlyFile {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        self.file.seek(position)
    }
}

fn make_volume_identity(
    native_uuid: Option<crate::NativeUuid>,
    mount_source: &[u8],
    filesystem_type: &[u8],
    device: u64,
) -> VolumeIdentity {
    let mut hasher = Hasher::new();
    hasher.update(b"guiying.volume-identity.v1\0");
    let strength = if let Some(uuid) = native_uuid {
        hasher.update(b"strong-native-uuid\0");
        hasher.update(uuid.as_bytes());
        hash_bytes(&mut hasher, filesystem_type);
        IdentityStrength::Strong
    } else {
        hasher.update(b"weak-observation\0");
        hash_bytes(&mut hasher, mount_source);
        hash_bytes(&mut hasher, filesystem_type);
        hasher.update(&device.to_le_bytes());
        IdentityStrength::Weak
    };
    VolumeIdentity::new(
        KeyDigest::new(*hasher.finalize().as_bytes()),
        strength,
        native_uuid,
    )
}

fn make_mount_session_key(
    identity_key: KeyDigest,
    mount_source: &[u8],
    filesystem_type: &[u8],
    root: crate::RootObjectIdentity,
    mount_flags: u64,
) -> Result<KeyDigest, VolumeError> {
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|error| VolumeError::Entropy(error.to_string()))?;
    let mut hasher = Hasher::new();
    hasher.update(b"guiying.mount-session.v1\0");
    hasher.update(&nonce);
    hasher.update(identity_key.as_bytes());
    hash_bytes(&mut hasher, mount_source);
    hash_bytes(&mut hasher, filesystem_type);
    hasher.update(&root.device.to_le_bytes());
    hasher.update(&root.inode.to_le_bytes());
    hasher.update(&root.generation.to_le_bytes());
    hasher.update(&mount_flags.to_le_bytes());
    Ok(KeyDigest::new(*hasher.finalize().as_bytes()))
}

fn hash_bytes(hasher: &mut Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}
