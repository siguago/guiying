use blake3::Hasher;
use serde::Serialize;

use crate::{
    IdentityStrength, KeyDigest, NativePathEncoding, ReadOnlyFormatCapabilities, VolumeIdentity,
};

/// Version 2 separates stable namespace semantics from ephemeral mount
/// sessions. Version 1 profiles were session-bound and are legacy evidence.
pub const PATH_SEMANTICS_PROFILE_VERSION: u32 = 2;
/// Version 2 keys are defined only over exact mount-relative native paths.
pub const PATH_KEY_ALGORITHM_VERSION: u32 = 2;
/// Persisted version 1 values remain historical evidence only. This crate does
/// not expose a constructor that can turn them into a live open capability.
pub const LEGACY_PATH_SEMANTICS_PROFILE_VERSION: u32 = 1;
pub const LEGACY_PATH_KEY_ALGORITHM_VERSION: u32 = 1;

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
    Exact,
    Nfc,
    Nfd,
    NormalizingOther,
}

/// Canonical case-behavior evidence consumed by the persistence boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseBehaviorObservation {
    Sensitive,
    InsensitivePreserving,
    InsensitiveNonpreserving,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStrategy {
    /// Hash exact native bytes/code units. This can produce conservative
    /// aliases on a case-insensitive volume, but never invents equivalence.
    ExactNativeV1,
}

/// The largest scope in which namespace evidence may be reused.
///
/// This is evidence, not an authorization to open a path. Every filesystem
/// access still requires a live [`crate::BoundVolumeSession`] and its full
/// revalidation. Each variant documents its own non-open reuse boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceReuseScope {
    /// Strong logical-filesystem identity plus known case and Unicode semantics
    /// permit cross-session namespace reuse. The new mount session must still
    /// be independently verified.
    CrossSession,
    /// Strong logical-filesystem identity and known case behavior permit only a
    /// fresh, full child lineage when a caller independently matches the same
    /// logical filesystem UUID and exact native selected-root bytes.
    ///
    /// Unknown Unicode normalization prevents broader reuse. This scope does
    /// not prove the same physical medium or directory object and does not
    /// authorize hint reuse, a file open, or cursor continuation.
    FreshAttemptOnly,
    /// The identity evidence is too weak to associate observations made by a
    /// different bind, or case behavior is unknown or contradictory, even if
    /// its profile key happens to match.
    CurrentSessionOnly,
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
    reuse_scope: NamespaceReuseScope,
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
        hasher.update(b"guiying.path-semantics-profile.offline.v2\0");
        hasher.update(&PATH_SEMANTICS_PROFILE_VERSION.to_le_bytes());
        hasher.update(namespace_key.as_bytes());
        hasher.update(&[encoding.domain_byte()]);
        hash_tag(&mut hasher, b"case-sensitive:unknown\0");
        hash_tag(&mut hasher, b"case-preserving:unknown\0");
        hash_tag(&mut hasher, b"unicode-normalization:unknown\0");
        hash_tag(&mut hasher, b"key-strategy:exact-native-v1\0");
        hasher.update(&PATH_KEY_ALGORITHM_VERSION.to_le_bytes());

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
            reuse_scope: NamespaceReuseScope::CurrentSessionOnly,
        }
    }

    pub(crate) fn from_mount_observation(
        volume_identity: &VolumeIdentity,
        encoding: NativePathEncoding,
        capabilities: ReadOnlyFormatCapabilities,
    ) -> Self {
        Self::from_observed_semantics(
            volume_identity,
            encoding,
            capabilities,
            UnicodeNormalizationObservation::Unknown,
        )
    }

    fn from_observed_semantics(
        volume_identity: &VolumeIdentity,
        encoding: NativePathEncoding,
        capabilities: ReadOnlyFormatCapabilities,
        unicode_normalization: UnicodeNormalizationObservation,
    ) -> Self {
        let case_behavior =
            case_behavior(capabilities.case_sensitive, capabilities.case_preserving);
        let reuse_scope = if volume_identity.strength() == IdentityStrength::Strong
            && case_behavior != CaseBehaviorObservation::Unknown
        {
            if unicode_normalization == UnicodeNormalizationObservation::Unknown {
                NamespaceReuseScope::FreshAttemptOnly
            } else {
                NamespaceReuseScope::CrossSession
            }
        } else {
            NamespaceReuseScope::CurrentSessionOnly
        };
        let mut hasher = Hasher::new();
        hasher.update(b"guiying.namespace-profile.v1\0");
        hasher.update(&PATH_SEMANTICS_PROFILE_VERSION.to_le_bytes());
        hasher.update(volume_identity.key().as_bytes());
        hasher.update(&[encoding.domain_byte()]);
        hash_option_bool(&mut hasher, capabilities.case_sensitive);
        hash_option_bool(&mut hasher, capabilities.case_preserving);
        hash_unicode_normalization(&mut hasher, unicode_normalization);
        hash_tag(&mut hasher, b"key-strategy:exact-native-v1\0");
        hasher.update(&PATH_KEY_ALGORITHM_VERSION.to_le_bytes());

        Self {
            version: PATH_SEMANTICS_PROFILE_VERSION,
            profile_key: KeyDigest::new(*hasher.finalize().as_bytes()),
            origin: ProfileOrigin::SystemReadOnlyObservation,
            encoding,
            case_sensitive: capabilities.case_sensitive,
            case_preserving: capabilities.case_preserving,
            unicode_normalization,
            key_strategy: KeyStrategy::ExactNativeV1,
            key_algorithm_version: PATH_KEY_ALGORITHM_VERSION,
            reuse_scope,
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

    pub const fn case_behavior(&self) -> CaseBehaviorObservation {
        case_behavior(self.case_sensitive, self.case_preserving)
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

    pub const fn reuse_scope(&self) -> NamespaceReuseScope {
        self.reuse_scope
    }

    pub(crate) fn calculate_path_key(&self, raw: &[u8]) -> KeyDigest {
        let mut hasher = Hasher::new();
        hasher.update(b"guiying.path-key.v2\0");
        hasher.update(&self.key_algorithm_version.to_le_bytes());
        hasher.update(self.profile_key.as_bytes());
        hasher.update(&[self.encoding.domain_byte()]);
        hasher.update(&(raw.len() as u64).to_le_bytes());
        hasher.update(raw);
        KeyDigest::new(*hasher.finalize().as_bytes())
    }
}

const fn case_behavior(
    case_sensitive: Option<bool>,
    case_preserving: Option<bool>,
) -> CaseBehaviorObservation {
    match (case_sensitive, case_preserving) {
        (Some(true), Some(true)) => CaseBehaviorObservation::Sensitive,
        (Some(false), Some(true)) => CaseBehaviorObservation::InsensitivePreserving,
        (Some(false), Some(false)) => CaseBehaviorObservation::InsensitiveNonpreserving,
        _ => CaseBehaviorObservation::Unknown,
    }
}

fn hash_option_bool(hasher: &mut Hasher, value: Option<bool>) {
    hasher.update(&[match value {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    }]);
}

fn hash_unicode_normalization(hasher: &mut Hasher, value: UnicodeNormalizationObservation) {
    hash_tag(
        hasher,
        match value {
            UnicodeNormalizationObservation::Unknown => b"unicode-normalization:unknown\0",
            UnicodeNormalizationObservation::Exact => b"unicode-normalization:exact\0",
            UnicodeNormalizationObservation::Nfc => b"unicode-normalization:nfc\0",
            UnicodeNormalizationObservation::Nfd => b"unicode-normalization:nfd\0",
            UnicodeNormalizationObservation::NormalizingOther => {
                b"unicode-normalization:normalizing-other\0"
            }
        },
    );
}

fn hash_tag(hasher: &mut Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

#[cfg(test)]
pub(crate) fn test_profile(encoding: NativePathEncoding) -> PathSemanticsProfile {
    let identity = VolumeIdentity::new(KeyDigest::new([0x11; 32]), IdentityStrength::Strong, None);
    PathSemanticsProfile::from_mount_observation(
        &identity,
        encoding,
        ReadOnlyFormatCapabilities::default(),
    )
}

#[cfg(test)]
pub(crate) fn test_fresh_attempt_profile(encoding: NativePathEncoding) -> PathSemanticsProfile {
    let identity = VolumeIdentity::new(KeyDigest::new([0x12; 32]), IdentityStrength::Strong, None);
    PathSemanticsProfile::from_mount_observation(
        &identity,
        encoding,
        ReadOnlyFormatCapabilities {
            case_sensitive: Some(true),
            case_preserving: Some(true),
            ..ReadOnlyFormatCapabilities::default()
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(key_byte: u8, strength: IdentityStrength) -> VolumeIdentity {
        VolumeIdentity::new(KeyDigest::new([key_byte; 32]), strength, None)
    }

    fn legacy_v1_observed_profile_key() -> KeyDigest {
        let mut hasher = Hasher::new();
        hasher.update(b"guiying.path-semantics-profile.v1\0");
        hasher.update(&LEGACY_PATH_SEMANTICS_PROFILE_VERSION.to_le_bytes());
        hasher.update(&[0x11; 32]);
        hasher.update(&[0x22; 32]);
        hasher.update(&[NativePathEncoding::UnixBytes.domain_byte()]);
        hash_option_bool(&mut hasher, None);
        hash_option_bool(&mut hasher, None);
        hasher.update(b"unicode-normalization:unknown\0");
        hasher.update(b"key-strategy:exact-native-v1\0");
        KeyDigest::new(*hasher.finalize().as_bytes())
    }

    fn legacy_v1_path_key(profile_key: KeyDigest, raw: &[u8]) -> KeyDigest {
        let mut hasher = Hasher::new();
        hasher.update(b"guiying.path-key.v1\0");
        hasher.update(&LEGACY_PATH_KEY_ALGORITHM_VERSION.to_le_bytes());
        hasher.update(profile_key.as_bytes());
        hasher.update(&[NativePathEncoding::UnixBytes.domain_byte()]);
        hasher.update(&(raw.len() as u64).to_le_bytes());
        hasher.update(raw);
        KeyDigest::new(*hasher.finalize().as_bytes())
    }

    fn legacy_v1_offline_profile_key() -> KeyDigest {
        let mut hasher = Hasher::new();
        hasher.update(b"guiying.path-semantics-profile.offline.v1\0");
        hasher.update(&LEGACY_PATH_SEMANTICS_PROFILE_VERSION.to_le_bytes());
        hasher.update(&[0x33; 32]);
        hasher.update(&[NativePathEncoding::UnixBytes.domain_byte()]);
        hasher.update(b"case-sensitive:unknown\0");
        hasher.update(b"case-preserving:unknown\0");
        hasher.update(b"unicode-normalization:unknown\0");
        hasher.update(b"key-strategy:exact-native-v1\0");
        KeyDigest::new(*hasher.finalize().as_bytes())
    }

    #[test]
    fn legacy_and_current_hash_algorithms_have_fixed_golden_vectors() {
        let raw = b"DCIM/photo-\xff.jpg";
        let legacy_profile = legacy_v1_observed_profile_key();
        let current = PathSemanticsProfile::from_mount_observation(
            &identity(0x11, IdentityStrength::Strong),
            NativePathEncoding::UnixBytes,
            ReadOnlyFormatCapabilities::default(),
        );
        let offline = PathSemanticsProfile::conservative_offline(
            NativePathEncoding::UnixBytes,
            KeyDigest::new([0x33; 32]),
        );
        let actual = [
            legacy_profile.to_hex(),
            legacy_v1_path_key(legacy_profile, raw).to_hex(),
            legacy_v1_offline_profile_key().to_hex(),
            current.profile_key().to_hex(),
            current.calculate_path_key(raw).to_hex(),
            offline.profile_key().to_hex(),
        ];
        assert_eq!(
            actual,
            [
                "bc82b0c1dad74e9ec3e9eb6f254dad401f30bac535fce94e3ce55330a887b60b",
                "1e89a0eed40223add198f0dba9ff6e634dd9812c61b709034e7a71bb86c99d5d",
                "35e63bbc5066b7a9e7d6e4def13ea0f9f6c72139d32fffa1645cd1cdd933caa6",
                "ea51f6688b7a1f3d0e944b1ad727b7702b664bc8fdb11f4e1cf70e9146fda410",
                "af283c8ed9b9f270f0bf2cfab54fd87d92be6c392b3ceff24a895e575d79d91c",
                "b159cb2d94d869216140e13536c5c397556c95d28d399a315b062064f52314ec",
            ]
        );
    }

    #[test]
    fn strong_identity_with_known_case_and_unknown_unicode_is_fresh_attempt_only() {
        let capabilities = ReadOnlyFormatCapabilities {
            case_sensitive: Some(true),
            case_preserving: Some(true),
            persistent_object_ids: Some(true),
            symbolic_links: Some(true),
            hard_links: Some(true),
            timestamp_granularity_ns: None,
        };
        let strong = identity(0x11, IdentityStrength::Strong);
        let first = PathSemanticsProfile::from_mount_observation(
            &strong,
            NativePathEncoding::UnixBytes,
            capabilities,
        );
        let rebound = PathSemanticsProfile::from_mount_observation(
            &strong,
            NativePathEncoding::UnixBytes,
            capabilities,
        );
        assert_eq!(first.profile_key(), rebound.profile_key());
        assert_eq!(first.case_behavior(), CaseBehaviorObservation::Sensitive);
        assert_eq!(
            first.unicode_normalization(),
            UnicodeNormalizationObservation::Unknown
        );
        assert_eq!(first.reuse_scope(), NamespaceReuseScope::FreshAttemptOnly);
        assert_eq!(
            serde_json::to_string(&first.reuse_scope()).expect("serialize reuse scope"),
            "\"fresh_attempt_only\""
        );

        let weak = identity(0x22, IdentityStrength::Weak);
        let weak_profile = PathSemanticsProfile::from_mount_observation(
            &weak,
            NativePathEncoding::UnixBytes,
            capabilities,
        );
        assert_eq!(
            weak_profile.reuse_scope(),
            NamespaceReuseScope::CurrentSessionOnly
        );
    }

    #[test]
    fn known_unicode_on_strong_known_case_is_cross_session() {
        let capabilities = ReadOnlyFormatCapabilities {
            case_sensitive: Some(true),
            case_preserving: Some(true),
            ..ReadOnlyFormatCapabilities::default()
        };
        let strong = identity(0x23, IdentityStrength::Strong);
        for unicode_normalization in [
            UnicodeNormalizationObservation::Exact,
            UnicodeNormalizationObservation::Nfc,
            UnicodeNormalizationObservation::Nfd,
            UnicodeNormalizationObservation::NormalizingOther,
        ] {
            let known = PathSemanticsProfile::from_observed_semantics(
                &strong,
                NativePathEncoding::UnixBytes,
                capabilities,
                unicode_normalization,
            );
            assert_eq!(known.reuse_scope(), NamespaceReuseScope::CrossSession);
            assert_eq!(known.case_behavior(), CaseBehaviorObservation::Sensitive);
            assert_eq!(known.unicode_normalization(), unicode_normalization);
        }
    }

    #[test]
    fn weak_or_unknown_case_semantics_remain_session_scoped() {
        let strong = identity(0x25, IdentityStrength::Strong);
        let weak = identity(0x24, IdentityStrength::Weak);
        let weak_known = PathSemanticsProfile::from_observed_semantics(
            &weak,
            NativePathEncoding::UnixBytes,
            ReadOnlyFormatCapabilities {
                case_sensitive: Some(true),
                case_preserving: Some(true),
                ..ReadOnlyFormatCapabilities::default()
            },
            UnicodeNormalizationObservation::Exact,
        );
        assert_eq!(
            weak_known.reuse_scope(),
            NamespaceReuseScope::CurrentSessionOnly
        );

        let contradictory = PathSemanticsProfile::from_observed_semantics(
            &strong,
            NativePathEncoding::UnixBytes,
            ReadOnlyFormatCapabilities {
                case_sensitive: Some(true),
                case_preserving: Some(false),
                ..ReadOnlyFormatCapabilities::default()
            },
            UnicodeNormalizationObservation::Exact,
        );
        assert_eq!(
            contradictory.case_behavior(),
            CaseBehaviorObservation::Unknown
        );
        assert_eq!(
            contradictory.reuse_scope(),
            NamespaceReuseScope::CurrentSessionOnly
        );

        let unknown_case_and_unicode = PathSemanticsProfile::from_observed_semantics(
            &strong,
            NativePathEncoding::UnixBytes,
            ReadOnlyFormatCapabilities::default(),
            UnicodeNormalizationObservation::Unknown,
        );
        assert_eq!(
            unknown_case_and_unicode.reuse_scope(),
            NamespaceReuseScope::CurrentSessionOnly
        );
    }

    #[test]
    fn volume_or_observed_path_semantics_changes_the_namespace_key() {
        let first_identity = identity(0x31, IdentityStrength::Strong);
        let second_identity = identity(0x32, IdentityStrength::Strong);
        let baseline_capabilities = ReadOnlyFormatCapabilities {
            case_sensitive: Some(false),
            case_preserving: Some(true),
            ..ReadOnlyFormatCapabilities::default()
        };
        let changed_capabilities = ReadOnlyFormatCapabilities {
            case_sensitive: Some(true),
            ..baseline_capabilities
        };
        let baseline = PathSemanticsProfile::from_mount_observation(
            &first_identity,
            NativePathEncoding::UnixBytes,
            baseline_capabilities,
        );
        let different_volume = PathSemanticsProfile::from_mount_observation(
            &second_identity,
            NativePathEncoding::UnixBytes,
            baseline_capabilities,
        );
        let different_semantics = PathSemanticsProfile::from_mount_observation(
            &first_identity,
            NativePathEncoding::UnixBytes,
            changed_capabilities,
        );

        assert_ne!(baseline.profile_key(), different_volume.profile_key());
        assert_ne!(baseline.profile_key(), different_semantics.profile_key());
    }
}
