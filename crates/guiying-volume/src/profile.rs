use blake3::Hasher;
use serde::Serialize;

use crate::{KeyDigest, NativePathEncoding, ReadOnlyFormatCapabilities};

pub const PATH_SEMANTICS_PROFILE_VERSION: u32 = 1;
pub const PATH_KEY_ALGORITHM_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileOrigin {
    SystemReadOnlyObservation,
    /// A validation-only profile with unknown filesystem semantics. Paths
    /// created from it cannot be opened by a bound volume session.
    ConservativeOffline,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnicodeNormalizationObservation {
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStrategy {
    /// Hash exact native bytes/code units. This can produce conservative
    /// aliases on a case-insensitive volume, but never invents equivalence.
    ExactNativeV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PathSemanticsProfile {
    version: u32,
    profile_key: KeyDigest,
    origin: ProfileOrigin,
    encoding: NativePathEncoding,
    case_sensitive: Option<bool>,
    case_preserving: Option<bool>,
    unicode_normalization: UnicodeNormalizationObservation,
    key_strategy: KeyStrategy,
    key_algorithm_version: u32,
}

impl PathSemanticsProfile {
    /// Create a validation-only profile for importing native path bytes when
    /// no supported volume backend is available.
    ///
    /// `namespace_key` should identify the caller's import namespace. This
    /// constructor never claims observed case or Unicode behavior, and its
    /// profile key cannot match a system-observed bound session profile.
    pub fn conservative_offline(encoding: NativePathEncoding, namespace_key: KeyDigest) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(b"guiying.path-semantics-profile.offline.v1\0");
        hasher.update(&PATH_SEMANTICS_PROFILE_VERSION.to_le_bytes());
        hasher.update(namespace_key.as_bytes());
        hasher.update(&[encoding.domain_byte()]);
        hasher.update(b"case-sensitive:unknown\0");
        hasher.update(b"case-preserving:unknown\0");
        hasher.update(b"unicode-normalization:unknown\0");
        hasher.update(b"key-strategy:exact-native-v1\0");

        Self {
            version: PATH_SEMANTICS_PROFILE_VERSION,
            profile_key: KeyDigest::new(*hasher.finalize().as_bytes()),
            origin: ProfileOrigin::ConservativeOffline,
            encoding,
            case_sensitive: None,
            case_preserving: None,
            unicode_normalization: UnicodeNormalizationObservation::Unknown,
            key_strategy: KeyStrategy::ExactNativeV1,
            key_algorithm_version: PATH_KEY_ALGORITHM_VERSION,
        }
    }

    pub(crate) fn from_mount_observation(
        volume_identity_key: KeyDigest,
        mount_session_key: KeyDigest,
        encoding: NativePathEncoding,
        capabilities: ReadOnlyFormatCapabilities,
    ) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(b"guiying.path-semantics-profile.v1\0");
        hasher.update(&PATH_SEMANTICS_PROFILE_VERSION.to_le_bytes());
        hasher.update(volume_identity_key.as_bytes());
        hasher.update(mount_session_key.as_bytes());
        hasher.update(&[encoding.domain_byte()]);
        hash_option_bool(&mut hasher, capabilities.case_sensitive);
        hash_option_bool(&mut hasher, capabilities.case_preserving);
        hasher.update(b"unicode-normalization:unknown\0");
        hasher.update(b"key-strategy:exact-native-v1\0");

        Self {
            version: PATH_SEMANTICS_PROFILE_VERSION,
            profile_key: KeyDigest::new(*hasher.finalize().as_bytes()),
            origin: ProfileOrigin::SystemReadOnlyObservation,
            encoding,
            case_sensitive: capabilities.case_sensitive,
            case_preserving: capabilities.case_preserving,
            unicode_normalization: UnicodeNormalizationObservation::Unknown,
            key_strategy: KeyStrategy::ExactNativeV1,
            key_algorithm_version: PATH_KEY_ALGORITHM_VERSION,
        }
    }

    pub const fn version(&self) -> u32 {
        self.version
    }

    pub const fn profile_key(&self) -> KeyDigest {
        self.profile_key
    }

    pub const fn origin(&self) -> ProfileOrigin {
        self.origin
    }

    pub const fn encoding(&self) -> NativePathEncoding {
        self.encoding
    }

    pub const fn case_sensitive(&self) -> Option<bool> {
        self.case_sensitive
    }

    pub const fn case_preserving(&self) -> Option<bool> {
        self.case_preserving
    }

    pub const fn unicode_normalization(&self) -> UnicodeNormalizationObservation {
        self.unicode_normalization
    }

    pub const fn key_strategy(&self) -> KeyStrategy {
        self.key_strategy
    }

    pub const fn key_algorithm_version(&self) -> u32 {
        self.key_algorithm_version
    }

    pub(crate) fn calculate_path_key(&self, raw: &[u8]) -> KeyDigest {
        let mut hasher = Hasher::new();
        hasher.update(b"guiying.path-key.v1\0");
        hasher.update(&self.key_algorithm_version.to_le_bytes());
        hasher.update(self.profile_key.as_bytes());
        hasher.update(&[self.encoding.domain_byte()]);
        hasher.update(&(raw.len() as u64).to_le_bytes());
        hasher.update(raw);
        KeyDigest::new(*hasher.finalize().as_bytes())
    }
}

fn hash_option_bool(hasher: &mut Hasher, value: Option<bool>) {
    hasher.update(&[match value {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    }]);
}

#[cfg(test)]
pub(crate) fn test_profile(encoding: NativePathEncoding) -> PathSemanticsProfile {
    PathSemanticsProfile::from_mount_observation(
        KeyDigest::new([0x11; 32]),
        KeyDigest::new([0x22; 32]),
        encoding,
        ReadOnlyFormatCapabilities::default(),
    )
}
