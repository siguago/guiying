use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use blake3::Hasher;

use crate::model::{
    BoundRootEvidence, IdentityStrength, KeyDigest, NativePathEncoding, VolumeIdentity,
};
use crate::platform::{self, PlatformSession};
use crate::{
    FileObjectIdentity, MountRelativePath, NativeValue, PathError, PathSemanticsProfile,
    RootRelativePath, RootScopeKey, VolumeError, VolumeObservation, MAX_RELATIVE_PATH_BYTES,
};

pub const MAX_ROOT_PATH_BYTES: usize = 64 * 1024;

pub struct BoundVolumeSession {
    inner: PlatformSession,
    observation: VolumeObservation,
    mount_relative_root_raw: Vec<u8>,
}

/// A current-session open locator paired with stable mount-relative evidence.
///
/// The root-relative portion is never serialized and this type cannot be
/// constructed outside the bound session. A [`MountRelativePath`] may be
/// persisted as namespace evidence, but it is deliberately insufficient for
/// opening a file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundMediaPath {
    root_relative: RootRelativePath,
    mount_relative: MountRelativePath,
}

impl BoundMediaPath {
    pub const fn root_relative(&self) -> &RootRelativePath {
        &self.root_relative
    }

    pub const fn mount_relative(&self) -> &MountRelativePath {
        &self.mount_relative
    }

    pub const fn stable_path_key(&self) -> KeyDigest {
        self.mount_relative.stable_path_key()
    }
}

impl BoundVolumeSession {
    /// Bind an absolute directory root without following any path component.
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
            &identity,
            NativePathEncoding::UnixBytes,
            parts.format_capabilities,
        );
        let mount_relative_root_raw = parts.mount_relative_root_raw;
        let stable_root = MountRelativePath::from_raw(
            mount_relative_root_raw.clone(),
            path_semantics.encoding(),
            &path_semantics,
        )?;
        let root_scope_key = make_root_scope_key(
            identity.key(),
            path_semantics.profile_key(),
            path_semantics.encoding(),
            stable_root.raw(),
        );
        let mount_relative_root =
            NativeValue::from_raw(stable_root.raw(), path_semantics.encoding());
        let observation = VolumeObservation::new(
            identity,
            mount_session_key,
            parts.mount,
            parts.root_identity,
            BoundRootEvidence {
                mount_relative_root,
                stable_root_path_key: stable_root.stable_path_key(),
                root_scope_key,
            },
            parts.format_capabilities,
            path_semantics,
        );
        Ok(Self {
            inner,
            observation,
            mount_relative_root_raw,
        })
    }

    pub const fn observation(&self) -> &VolumeObservation {
        &self.observation
    }

    pub const fn path_semantics(&self) -> &PathSemanticsProfile {
        self.observation.path_semantics()
    }

    /// Validate a selected-root-relative locator and bind it to this exact
    /// mount session. Stable evidence is calculated over the complete path
    /// relative to the real filesystem mount root.
    pub fn relative_path(&self, raw: Vec<u8>) -> Result<BoundMediaPath, PathError> {
        let root_relative = RootRelativePath::from_raw(
            raw,
            self.path_semantics().encoding(),
            self.observation.mount_session_key(),
        )?;
        let mount_relative = combine_mount_relative(
            &self.mount_relative_root_raw,
            &root_relative,
            self.path_semantics(),
        )?;
        Ok(BoundMediaPath {
            root_relative,
            mount_relative,
        })
    }

    /// Recheck descriptor identity, mount metadata, native UUID, and the
    /// original selected path. Any mismatch invalidates the current session.
    pub fn revalidate(&self) -> Result<(), VolumeError> {
        platform::revalidate(&self.inner)
    }

    /// Reopen a directory component-by-component from the selected root and
    /// return its current identity only after two matching, full mount-session
    /// checks. No descriptor escapes this crate.
    pub fn verify_directory(
        &self,
        path: &BoundMediaPath,
    ) -> Result<crate::RootObjectIdentity, VolumeError> {
        validate_bound_media_path(self, path)?;
        let components: Vec<&[u8]> = path.root_relative.unix_components()?.collect();
        platform::verify_directory(&self.inner, &components)
    }

    /// Open a regular file component-by-component from the bound root.
    ///
    /// Every ancestor and the final component use no-follow semantics. A
    /// nested mount is rejected by device identity. The mount session is
    /// revalidated both before and after the open.
    pub fn open_regular_file(&self, path: &BoundMediaPath) -> Result<ReadOnlyFile, VolumeError> {
        validate_bound_media_path(self, path)?;
        if path.root_relative.is_root() {
            return Err(PathError::RootIsNotAFile.into());
        }
        let components: Vec<&[u8]> = path.root_relative.unix_components()?.collect();
        let (file, identity) = platform::open_regular_file(&self.inner, &components)?;
        Ok(ReadOnlyFile {
            file,
            initial_identity: identity,
            mount_session_key: self.observation.mount_session_key(),
            root_relative_path_raw: path.root_relative.raw().to_vec(),
            mount_relative_path_raw: path.mount_relative.raw().to_vec(),
            stable_path_key: path.stable_path_key(),
        })
    }
}

pub struct ReadOnlyFile {
    file: File,
    initial_identity: FileObjectIdentity,
    mount_session_key: KeyDigest,
    root_relative_path_raw: Vec<u8>,
    mount_relative_path_raw: Vec<u8>,
    stable_path_key: KeyDigest,
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
        path: &BoundMediaPath,
    ) -> Result<bool, VolumeError> {
        if self.mount_session_key != session.observation.mount_session_key() {
            return Err(VolumeError::FileSessionMismatch);
        }
        validate_bound_media_path(session, path)?;
        if self.root_relative_path_raw != path.root_relative.raw()
            || self.mount_relative_path_raw != path.mount_relative.raw()
            || self.stable_path_key != path.stable_path_key()
        {
            return Err(VolumeError::FilePathMismatch);
        }

        session.revalidate()?;
        let descriptor_before = platform::snapshot_file(&self.file)?;
        if descriptor_before != self.initial_identity {
            return Ok(false);
        }
        let components: Vec<&[u8]> = path.root_relative.unix_components()?.collect();
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

fn validate_bound_media_path(
    session: &BoundVolumeSession,
    path: &BoundMediaPath,
) -> Result<(), VolumeError> {
    validate_bound_media_path_parts(
        session.path_semantics(),
        &session.mount_relative_root_raw,
        session.observation.mount_session_key(),
        path,
    )
}

fn validate_bound_media_path_parts(
    profile: &PathSemanticsProfile,
    mount_relative_root_raw: &[u8],
    mount_session_key: KeyDigest,
    path: &BoundMediaPath,
) -> Result<(), VolumeError> {
    if !path
        .root_relative
        .is_bound_to_mount_session(mount_session_key)
    {
        return Err(VolumeError::PathSessionMismatch);
    }
    if path.mount_relative.profile_key() != profile.profile_key() {
        return Err(PathError::ProfileMismatch.into());
    }
    let expected = combine_mount_relative(mount_relative_root_raw, &path.root_relative, profile)?;
    if expected != path.mount_relative {
        return Err(VolumeError::FilePathMismatch);
    }
    Ok(())
}

fn combine_mount_relative(
    mount_relative_root: &[u8],
    root_relative: &RootRelativePath,
    profile: &PathSemanticsProfile,
) -> Result<MountRelativePath, PathError> {
    if profile.encoding() != NativePathEncoding::UnixBytes
        || root_relative.encoding() != NativePathEncoding::UnixBytes
    {
        return Err(PathError::UnsupportedEncoding);
    }
    let separator_bytes = usize::from(!mount_relative_root.is_empty() && !root_relative.is_root());
    let combined_len = mount_relative_root
        .len()
        .checked_add(separator_bytes)
        .and_then(|length| length.checked_add(root_relative.raw().len()))
        .ok_or(PathError::PathTooLong {
            limit: MAX_RELATIVE_PATH_BYTES,
        })?;
    if combined_len > MAX_RELATIVE_PATH_BYTES {
        return Err(PathError::PathTooLong {
            limit: MAX_RELATIVE_PATH_BYTES,
        });
    }
    let mut combined = Vec::with_capacity(combined_len);
    combined.extend_from_slice(mount_relative_root);
    if separator_bytes != 0 {
        combined.push(b'/');
    }
    combined.extend_from_slice(root_relative.raw());
    MountRelativePath::from_raw(combined, profile.encoding(), profile)
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

fn make_root_scope_key(
    identity_key: KeyDigest,
    namespace_profile_key: KeyDigest,
    encoding: NativePathEncoding,
    mount_relative_root: &[u8],
) -> RootScopeKey {
    let mut hasher = Hasher::new();
    hasher.update(b"guiying.root-scope.v1\0");
    hasher.update(identity_key.as_bytes());
    hasher.update(namespace_profile_key.as_bytes());
    hasher.update(&[encoding.domain_byte()]);
    hash_bytes(&mut hasher, mount_relative_root);
    RootScopeKey::new(*hasher.finalize().as_bytes())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ReadOnlyFormatCapabilities;

    fn profile(identity_byte: u8) -> PathSemanticsProfile {
        let identity = VolumeIdentity::new(
            KeyDigest::new([identity_byte; 32]),
            IdentityStrength::Strong,
            None,
        );
        PathSemanticsProfile::from_mount_observation(
            &identity,
            NativePathEncoding::UnixBytes,
            ReadOnlyFormatCapabilities::default(),
        )
    }

    fn bound_path(
        profile: &PathSemanticsProfile,
        root: &[u8],
        child: &[u8],
        session: KeyDigest,
    ) -> BoundMediaPath {
        let root_relative =
            RootRelativePath::from_raw(child.to_vec(), NativePathEncoding::UnixBytes, session)
                .expect("valid root-relative path");
        let mount_relative = combine_mount_relative(root, &root_relative, profile)
            .expect("valid mount-relative path");
        BoundMediaPath {
            root_relative,
            mount_relative,
        }
    }

    #[test]
    fn every_open_locator_requires_the_exact_live_session() {
        let profile = profile(0x51);
        let first_session = KeyDigest::new([0x41; 32]);
        let second_session = KeyDigest::new([0x42; 32]);
        let path = bound_path(&profile, b"DCIM", b"a.jpg", first_session);
        assert!(validate_bound_media_path_parts(&profile, b"DCIM", first_session, &path).is_ok());
        assert!(matches!(
            validate_bound_media_path_parts(&profile, b"DCIM", second_session, &path),
            Err(VolumeError::PathSessionMismatch)
        ));
    }

    #[test]
    fn mount_relative_keys_distinguish_roots_and_converge_for_the_same_file() {
        let profile = profile(0x52);
        let session = KeyDigest::new([0x61; 32]);
        let from_a = bound_path(&profile, b"Pictures/A", b"photo.jpg", session);
        let from_b = bound_path(&profile, b"Pictures/B", b"photo.jpg", session);
        let from_parent = bound_path(&profile, b"Pictures", b"A/photo.jpg", session);

        assert_ne!(from_a.stable_path_key(), from_b.stable_path_key());
        assert_ne!(from_a.mount_relative().raw(), from_b.mount_relative().raw());
        assert_eq!(from_a.stable_path_key(), from_parent.stable_path_key());
        assert_eq!(
            from_a.mount_relative().raw(),
            from_parent.mount_relative().raw()
        );

        let non_utf8 = bound_path(
            &profile,
            b"Pictures/selected-\xff",
            b"photo-\xfe.jpg",
            session,
        );
        assert_eq!(
            non_utf8.mount_relative().raw(),
            b"Pictures/selected-\xff/photo-\xfe.jpg"
        );
    }

    #[test]
    fn combined_path_budgets_are_checked_before_allocation() {
        let profile = profile(0x53);
        let root_relative = RootRelativePath::from_raw(
            b"photo.jpg".to_vec(),
            NativePathEncoding::UnixBytes,
            KeyDigest::new([0x62; 32]),
        )
        .expect("valid child");
        let oversized_root = vec![b'a'; MAX_RELATIVE_PATH_BYTES];
        assert!(matches!(
            combine_mount_relative(&oversized_root, &root_relative, &profile),
            Err(PathError::PathTooLong { .. })
        ));

        let root_with_1024_components = (0..1024).map(|_| "a").collect::<Vec<_>>().join("/");
        assert!(matches!(
            combine_mount_relative(
                root_with_1024_components.as_bytes(),
                &root_relative,
                &profile
            ),
            Err(PathError::TooManyComponents { .. })
        ));
    }

    #[test]
    fn root_scope_is_stable_but_domain_separated_by_root_volume_and_profile() {
        let first_profile = profile(0x54);
        let second_profile = profile(0x55);
        let first_identity = KeyDigest::new([0x54; 32]);
        let second_identity = KeyDigest::new([0x56; 32]);
        let first = make_root_scope_key(
            first_identity,
            first_profile.profile_key(),
            NativePathEncoding::UnixBytes,
            b"Pictures/A",
        );
        assert_eq!(
            first.to_hex(),
            "5e2b799794ce6adfbd4bd70c7cf9c3d902c23323c94cb69f0e9353d38c71308d"
        );
        assert_eq!(
            first,
            make_root_scope_key(
                first_identity,
                first_profile.profile_key(),
                NativePathEncoding::UnixBytes,
                b"Pictures/A",
            )
        );
        assert_ne!(
            first,
            make_root_scope_key(
                first_identity,
                first_profile.profile_key(),
                NativePathEncoding::UnixBytes,
                b"Pictures/B",
            )
        );
        assert_ne!(
            first,
            make_root_scope_key(
                second_identity,
                first_profile.profile_key(),
                NativePathEncoding::UnixBytes,
                b"Pictures/A",
            )
        );
        assert_ne!(
            first,
            make_root_scope_key(
                first_identity,
                second_profile.profile_key(),
                NativePathEncoding::UnixBytes,
                b"Pictures/A",
            )
        );
    }
}
