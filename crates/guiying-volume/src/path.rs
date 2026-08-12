use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use serde::Serialize;

use crate::{KeyDigest, NativePathEncoding, PathError, PathSemanticsProfile};

pub const MAX_RELATIVE_PATH_BYTES: usize = 64 * 1024;
pub const MAX_PATH_COMPONENTS: usize = 1024;
pub const MAX_COMPONENT_BYTES: usize = 16 * 1024;
pub const MAX_DISPLAY_PATH_BYTES: usize = MAX_RELATIVE_PATH_BYTES * 3;
const MAX_BASE64_PATH_BYTES: usize = MAX_RELATIVE_PATH_BYTES.div_ceil(3) * 4;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SerializedMountRelativePath {
    pub display: String,
    pub encoding: NativePathEncoding,
    pub raw_base64: String,
    pub profile_key: KeyDigest,
    pub stable_path_key: KeyDigest,
}

/// A stable namespace address relative to the real filesystem mount root.
///
/// This type is exact-native evidence only and is never accepted as an open,
/// hint-reuse, or cursor-continuation authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountRelativePath {
    encoding: NativePathEncoding,
    raw: Vec<u8>,
    display: String,
    profile_key: KeyDigest,
    stable_path_key: KeyDigest,
    component_count: usize,
}

impl MountRelativePath {
    pub fn from_raw(
        raw: Vec<u8>,
        encoding: NativePathEncoding,
        profile: &PathSemanticsProfile,
    ) -> Result<Self, PathError> {
        if encoding != profile.encoding() {
            return Err(PathError::EncodingProfileMismatch);
        }
        if raw.len() > MAX_RELATIVE_PATH_BYTES {
            return Err(PathError::PathTooLong {
                limit: MAX_RELATIVE_PATH_BYTES,
            });
        }

        let component_count = match encoding {
            NativePathEncoding::UnixBytes => validate_unix(&raw)?,
            NativePathEncoding::WindowsUtf16Le => validate_windows(&raw)?,
        };
        let display = display_raw(&raw, encoding);
        let profile_key = profile.profile_key();
        let stable_path_key = profile.calculate_path_key(&raw);
        Ok(Self {
            encoding,
            raw,
            display,
            profile_key,
            stable_path_key,
            component_count,
        })
    }

    pub fn from_serialized(
        serialized: SerializedMountRelativePath,
        profile: &PathSemanticsProfile,
    ) -> Result<Self, PathError> {
        if serialized.profile_key != profile.profile_key() {
            return Err(PathError::ProfileMismatch);
        }
        if serialized.display.len() > MAX_DISPLAY_PATH_BYTES {
            return Err(PathError::DisplayTooLong {
                limit: MAX_DISPLAY_PATH_BYTES,
            });
        }
        if serialized.raw_base64.len() > MAX_BASE64_PATH_BYTES {
            return Err(PathError::PathTooLong {
                limit: MAX_RELATIVE_PATH_BYTES,
            });
        }
        let raw = STANDARD_NO_PAD
            .decode(&serialized.raw_base64)
            .map_err(|error| PathError::InvalidBase64(error.to_string()))?;
        if STANDARD_NO_PAD.encode(&raw) != serialized.raw_base64 {
            return Err(PathError::InvalidBase64(
                "non-canonical encoding".to_owned(),
            ));
        }
        let path = Self::from_raw(raw, serialized.encoding, profile)?;
        if path.display != serialized.display {
            return Err(PathError::DisplayMismatch);
        }
        if path.stable_path_key != serialized.stable_path_key {
            return Err(PathError::PathKeyMismatch);
        }
        Ok(path)
    }

    pub fn to_serialized(&self) -> SerializedMountRelativePath {
        SerializedMountRelativePath {
            display: self.display.clone(),
            encoding: self.encoding,
            raw_base64: STANDARD_NO_PAD.encode(&self.raw),
            profile_key: self.profile_key,
            stable_path_key: self.stable_path_key,
        }
    }

    pub const fn encoding(&self) -> NativePathEncoding {
        self.encoding
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    pub fn display(&self) -> &str {
        &self.display
    }

    pub const fn profile_key(&self) -> KeyDigest {
        self.profile_key
    }

    pub const fn stable_path_key(&self) -> KeyDigest {
        self.stable_path_key
    }

    pub const fn component_count(&self) -> usize {
        self.component_count
    }

    pub const fn is_root(&self) -> bool {
        self.component_count == 0
    }
}

/// A lossless locator relative to the selected scan root.
///
/// It has deliberately no namespace key or serialization and carries a private
/// exact-session binding. The volume session combines it with its descriptor-
/// verified mount-relative root before producing stable path evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootRelativePath {
    encoding: NativePathEncoding,
    raw: Vec<u8>,
    display: String,
    component_count: usize,
    mount_session_key: KeyDigest,
}

impl RootRelativePath {
    pub(crate) fn from_raw(
        raw: Vec<u8>,
        encoding: NativePathEncoding,
        mount_session_key: KeyDigest,
    ) -> Result<Self, PathError> {
        let component_count = validate_relative_raw(&raw, encoding)?;
        let display = display_raw(&raw, encoding);
        Ok(Self {
            encoding,
            raw,
            display,
            component_count,
            mount_session_key,
        })
    }

    pub const fn encoding(&self) -> NativePathEncoding {
        self.encoding
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    pub fn display(&self) -> &str {
        &self.display
    }

    pub const fn component_count(&self) -> usize {
        self.component_count
    }

    pub const fn is_root(&self) -> bool {
        self.component_count == 0
    }

    pub(crate) fn is_bound_to_mount_session(&self, mount_session_key: KeyDigest) -> bool {
        self.mount_session_key == mount_session_key
    }

    pub(crate) fn unix_components(&self) -> Result<impl Iterator<Item = &[u8]>, PathError> {
        if self.encoding != NativePathEncoding::UnixBytes {
            return Err(PathError::UnsupportedEncoding);
        }
        Ok(self
            .raw
            .split(|byte| *byte == b'/')
            .filter(|part| !part.is_empty()))
    }
}

pub(crate) fn validate_relative_raw(
    raw: &[u8],
    encoding: NativePathEncoding,
) -> Result<usize, PathError> {
    if raw.len() > MAX_RELATIVE_PATH_BYTES {
        return Err(PathError::PathTooLong {
            limit: MAX_RELATIVE_PATH_BYTES,
        });
    }
    match encoding {
        NativePathEncoding::UnixBytes => validate_unix(raw),
        NativePathEncoding::WindowsUtf16Le => validate_windows(raw),
    }
}

pub(crate) fn display_raw(raw: &[u8], encoding: NativePathEncoding) -> String {
    match encoding {
        NativePathEncoding::UnixBytes => String::from_utf8_lossy(raw).into_owned(),
        NativePathEncoding::WindowsUtf16Le => {
            let units = raw
                .chunks_exact(2)
                .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]));
            std::char::decode_utf16(units)
                .map(|value| value.unwrap_or(char::REPLACEMENT_CHARACTER))
                .collect()
        }
    }
}

fn validate_unix(raw: &[u8]) -> Result<usize, PathError> {
    if raw.is_empty() {
        return Ok(0);
    }
    if raw[0] == b'/' {
        return Err(PathError::AbsolutePath);
    }
    if raw.contains(&0) {
        return Err(PathError::Nul);
    }

    let mut count = 0usize;
    for (index, component) in raw.split(|byte| *byte == b'/').enumerate() {
        validate_component_budget(index, component.len())?;
        if component.is_empty() {
            return Err(PathError::EmptyComponent { index });
        }
        if component == b"." {
            return Err(PathError::DotComponent { index });
        }
        if component == b".." {
            return Err(PathError::ParentComponent { index });
        }
        count += 1;
        if count > MAX_PATH_COMPONENTS {
            return Err(PathError::TooManyComponents {
                limit: MAX_PATH_COMPONENTS,
            });
        }
    }
    Ok(count)
}

fn validate_windows(raw: &[u8]) -> Result<usize, PathError> {
    if raw.len() % 2 != 0 {
        return Err(PathError::InvalidUtf16Length);
    }
    if raw.is_empty() {
        return Ok(0);
    }
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
        .collect();
    if is_windows_separator(units[0]) {
        return Err(PathError::AbsolutePath);
    }
    if units.contains(&0) {
        return Err(PathError::Nul);
    }
    if units.contains(&(b':' as u16)) {
        return Err(PathError::WindowsAdsOrDrive);
    }

    let mut count = 0usize;
    for (index, component) in units.split(|unit| is_windows_separator(*unit)).enumerate() {
        validate_component_budget(index, component.len().saturating_mul(2))?;
        if component.is_empty() {
            return Err(PathError::EmptyComponent { index });
        }
        if component == [b'.' as u16] {
            return Err(PathError::DotComponent { index });
        }
        if component == [b'.' as u16, b'.' as u16] {
            return Err(PathError::ParentComponent { index });
        }
        if component
            .last()
            .is_some_and(|unit| matches!(*unit, 0x20 | 0x2e))
        {
            return Err(PathError::WindowsAmbiguousTrailingCharacter { index });
        }
        if component.iter().any(|unit| {
            *unit < 0x20
                || matches!(
                    *unit,
                    value if value == b'<' as u16
                        || value == b'>' as u16
                        || value == b'"' as u16
                        || value == b'|' as u16
                        || value == b'?' as u16
                        || value == b'*' as u16
                )
        }) {
            return Err(PathError::WindowsForbiddenCharacter { index });
        }
        if is_windows_device(component) {
            return Err(PathError::WindowsReservedDevice { index });
        }
        count += 1;
        if count > MAX_PATH_COMPONENTS {
            return Err(PathError::TooManyComponents {
                limit: MAX_PATH_COMPONENTS,
            });
        }
    }
    Ok(count)
}

fn validate_component_budget(index: usize, bytes: usize) -> Result<(), PathError> {
    if bytes > MAX_COMPONENT_BYTES {
        return Err(PathError::ComponentTooLong {
            index,
            limit: MAX_COMPONENT_BYTES,
        });
    }
    Ok(())
}

fn is_windows_separator(unit: u16) -> bool {
    unit == b'\\' as u16 || unit == b'/' as u16
}

fn is_windows_device(component: &[u16]) -> bool {
    let stem_end = component
        .iter()
        .position(|unit| *unit == b'.' as u16)
        .unwrap_or(component.len());
    let stem: Vec<u16> = component[..stem_end]
        .iter()
        .map(|unit| unit.to_ascii_uppercase())
        .collect();
    matches_ascii(&stem, b"CON")
        || matches_ascii(&stem, b"PRN")
        || matches_ascii(&stem, b"AUX")
        || matches_ascii(&stem, b"NUL")
        || matches_ascii(&stem, b"CLOCK$")
        || matches_ascii(&stem, b"CONIN$")
        || matches_ascii(&stem, b"CONOUT$")
        || numbered_windows_device(&stem, b"COM")
        || numbered_windows_device(&stem, b"LPT")
}

fn numbered_windows_device(stem: &[u16], prefix: &[u8; 3]) -> bool {
    if stem.len() != 4 || !matches_ascii(&stem[..3], prefix) {
        return false;
    }
    matches!(stem[3], value if (b'0' as u16..=b'9' as u16).contains(&value))
        || matches!(stem[3], 0x00b9 | 0x00b2 | 0x00b3)
}

fn matches_ascii(units: &[u16], ascii: &[u8]) -> bool {
    units.len() == ascii.len()
        && units
            .iter()
            .zip(ascii)
            .all(|(unit, byte)| *unit == *byte as u16)
}

trait U16AsciiUppercase {
    fn to_ascii_uppercase(self) -> Self;
}

impl U16AsciiUppercase for u16 {
    fn to_ascii_uppercase(self) -> Self {
        if (b'a' as u16..=b'z' as u16).contains(&self) {
            self - (b'a' - b'A') as u16
        } else {
            self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{test_fresh_attempt_profile, test_profile};

    fn windows_raw(value: &[u16]) -> Vec<u8> {
        value.iter().flat_map(|unit| unit.to_le_bytes()).collect()
    }

    fn windows_text(value: &str) -> Vec<u8> {
        windows_raw(&value.encode_utf16().collect::<Vec<_>>())
    }

    #[test]
    fn unix_paths_are_lossless_and_profile_bound() {
        let profile = test_profile(NativePathEncoding::UnixBytes);
        let raw = b"photos/non-utf8-\xff.jpg".to_vec();
        let path = MountRelativePath::from_raw(raw.clone(), profile.encoding(), &profile)
            .expect("valid path");
        assert_eq!(path.raw(), raw);
        assert_eq!(path.component_count(), 2);
        let serialized = path.to_serialized();
        assert_eq!(
            MountRelativePath::from_serialized(serialized, &profile).expect("round trip"),
            path
        );
    }

    #[test]
    fn fresh_attempt_paths_preserve_exact_native_distinctions() {
        let profile = test_fresh_attempt_profile(NativePathEncoding::UnixBytes);
        assert_eq!(
            profile.reuse_scope(),
            crate::NamespaceReuseScope::FreshAttemptOnly
        );

        let nfc = MountRelativePath::from_raw(
            "photos/caf\u{e9}.jpg".as_bytes().to_vec(),
            profile.encoding(),
            &profile,
        )
        .expect("NFC path");
        let nfd = MountRelativePath::from_raw(
            "photos/cafe\u{301}.jpg".as_bytes().to_vec(),
            profile.encoding(),
            &profile,
        )
        .expect("NFD path");
        let case_variant = MountRelativePath::from_raw(
            b"photos/CAF\xC3\x89.JPG".to_vec(),
            profile.encoding(),
            &profile,
        )
        .expect("case-variant path");

        assert_ne!(nfc.raw(), nfd.raw());
        assert_ne!(nfc.stable_path_key(), nfd.stable_path_key());
        assert_ne!(nfc.stable_path_key(), case_variant.stable_path_key());
        assert_eq!(
            MountRelativePath::from_serialized(nfc.to_serialized(), &profile)
                .expect("exact-native round trip")
                .raw(),
            nfc.raw()
        );
    }

    #[test]
    fn unix_paths_reject_escapes_and_ambiguity() {
        let profile = test_profile(NativePathEncoding::UnixBytes);
        for raw in [
            b"/absolute".as_slice(),
            b"a/../b".as_slice(),
            b"a/./b".as_slice(),
            b"a//b".as_slice(),
            b"a\0b".as_slice(),
        ] {
            assert!(
                MountRelativePath::from_raw(raw.to_vec(), profile.encoding(), &profile).is_err()
            );
        }
    }

    #[test]
    fn windows_paths_reject_ads_roots_devices_and_ambiguous_names() {
        let profile = test_profile(NativePathEncoding::WindowsUtf16Le);
        for value in [
            r"C:\photo.jpg",
            r"\\server\share",
            r"photo.jpg:secret",
            r"folder\..\photo.jpg",
            r"folder\CON.txt",
            r"folder\com1",
            "folder\\trailing. ",
        ] {
            assert!(
                MountRelativePath::from_raw(windows_text(value), profile.encoding(), &profile)
                    .is_err()
            );
        }
    }

    #[test]
    fn root_relative_empty_path_has_a_distinct_key() {
        let profile = test_profile(NativePathEncoding::UnixBytes);
        let root = MountRelativePath::from_raw(Vec::new(), profile.encoding(), &profile)
            .expect("root path");
        assert!(root.is_root());
        assert_ne!(root.stable_path_key(), KeyDigest::new([0; 32]));
    }

    #[test]
    fn tampered_serialization_is_rejected() {
        let profile = test_profile(NativePathEncoding::UnixBytes);
        let path = MountRelativePath::from_raw(b"a.jpg".to_vec(), profile.encoding(), &profile)
            .expect("valid path");
        let mut serialized = path.to_serialized();
        serialized.display = "b.jpg".to_owned();
        assert!(matches!(
            MountRelativePath::from_serialized(serialized, &profile),
            Err(PathError::DisplayMismatch)
        ));

        let mut serialized = path.to_serialized();
        serialized.stable_path_key = KeyDigest::from_bytes([0xff; 32]);
        assert!(matches!(
            MountRelativePath::from_serialized(serialized, &profile),
            Err(PathError::PathKeyMismatch)
        ));

        let mut serialized = path.to_serialized();
        serialized.encoding = NativePathEncoding::WindowsUtf16Le;
        assert!(matches!(
            MountRelativePath::from_serialized(serialized, &profile),
            Err(PathError::EncodingProfileMismatch)
        ));
    }

    #[test]
    fn oversized_serialized_display_is_rejected() {
        let profile = test_profile(NativePathEncoding::UnixBytes);
        let path = MountRelativePath::from_raw(b"a.jpg".to_vec(), profile.encoding(), &profile)
            .expect("valid path");
        let mut serialized = path.to_serialized();
        serialized.display = "a".repeat(MAX_DISPLAY_PATH_BYTES + 1);
        assert!(matches!(
            MountRelativePath::from_serialized(serialized, &profile),
            Err(PathError::DisplayTooLong { .. })
        ));
    }

    #[test]
    fn malformed_utf16_is_rejected_without_allocation_growth() {
        let profile = test_profile(NativePathEncoding::WindowsUtf16Le);
        assert!(matches!(
            MountRelativePath::from_raw(vec![1], profile.encoding(), &profile),
            Err(PathError::InvalidUtf16Length)
        ));
        assert_eq!(windows_raw(&[0xd800]).len(), 2);
    }

    #[test]
    fn hard_path_budgets_are_enforced() {
        let profile = test_profile(NativePathEncoding::UnixBytes);
        assert!(matches!(
            MountRelativePath::from_raw(
                vec![b'a'; MAX_RELATIVE_PATH_BYTES + 1],
                profile.encoding(),
                &profile
            ),
            Err(PathError::PathTooLong { .. })
        ));
        assert!(matches!(
            MountRelativePath::from_raw(
                vec![b'a'; MAX_COMPONENT_BYTES + 1],
                profile.encoding(),
                &profile
            ),
            Err(PathError::ComponentTooLong { .. })
        ));

        let too_many = std::iter::repeat("a")
            .take(MAX_PATH_COMPONENTS + 1)
            .collect::<Vec<_>>()
            .join("/");
        assert!(matches!(
            MountRelativePath::from_raw(too_many.into_bytes(), profile.encoding(), &profile),
            Err(PathError::TooManyComponents { .. })
        ));
    }

    #[test]
    fn serialization_rejects_noncanonical_base64_and_wrong_profile() {
        let first = test_profile(NativePathEncoding::UnixBytes);
        let second_identity = crate::VolumeIdentity::new(
            KeyDigest::new([0x33; 32]),
            crate::IdentityStrength::Strong,
            None,
        );
        let second = PathSemanticsProfile::from_mount_observation(
            &second_identity,
            NativePathEncoding::UnixBytes,
            crate::ReadOnlyFormatCapabilities::default(),
        );
        let path = MountRelativePath::from_raw(b"a.jpg".to_vec(), first.encoding(), &first)
            .expect("valid path");
        let mut serialized = path.to_serialized();
        serialized.raw_base64.push('=');
        assert!(matches!(
            MountRelativePath::from_serialized(serialized, &first),
            Err(PathError::InvalidBase64(_))
        ));
        assert!(matches!(
            MountRelativePath::from_serialized(path.to_serialized(), &second),
            Err(PathError::ProfileMismatch)
        ));
    }

    #[test]
    fn windows_extended_device_names_are_rejected() {
        let profile = test_profile(NativePathEncoding::WindowsUtf16Le);
        for value in [
            r"folder\CONIN$",
            r"folder\conout$.txt",
            r"folder\COM0",
            r"folder\lpt0.log",
            "folder\\COM¹",
        ] {
            assert!(matches!(
                MountRelativePath::from_raw(windows_text(value), profile.encoding(), &profile),
                Err(PathError::WindowsReservedDevice { .. })
            ));
        }
    }

    #[test]
    fn offline_profile_is_conservative_and_namespace_bound() {
        let first = PathSemanticsProfile::conservative_offline(
            NativePathEncoding::WindowsUtf16Le,
            KeyDigest::from_bytes([0x55; 32]),
        );
        let second = PathSemanticsProfile::conservative_offline(
            NativePathEncoding::WindowsUtf16Le,
            KeyDigest::from_bytes([0x66; 32]),
        );
        assert_eq!(first.case_sensitive(), None);
        assert_eq!(first.case_preserving(), None);
        assert_eq!(first.origin(), crate::ProfileOrigin::ConservativeOffline);
        assert_eq!(
            first.reuse_scope(),
            crate::NamespaceReuseScope::CurrentSessionOnly
        );
        assert_ne!(first.profile_key(), second.profile_key());

        let raw = windows_text(r"photos\safe.jpg");
        let path = MountRelativePath::from_raw(raw, first.encoding(), &first)
            .expect("safe offline Windows path");
        assert!(matches!(
            MountRelativePath::from_serialized(path.to_serialized(), &second),
            Err(PathError::ProfileMismatch)
        ));
    }

    #[test]
    fn mount_relative_evidence_is_stable_and_contains_no_session_nonce() {
        let profile = test_profile(NativePathEncoding::UnixBytes);
        let path = MountRelativePath::from_raw(
            b"photos/a.jpg".to_vec(),
            NativePathEncoding::UnixBytes,
            &profile,
        )
        .expect("valid path");

        let reconstructed = MountRelativePath::from_serialized(path.to_serialized(), &profile)
            .expect("stable path serialization");
        assert_eq!(path.stable_path_key(), reconstructed.stable_path_key());
    }
}
