use std::fmt;

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use serde::{Serialize, Serializer};

use crate::profile::PathSemanticsProfile;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeyDigest([u8; 32]);

impl KeyDigest {
    pub(crate) const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Reconstruct a persisted digest. Callers must still pass it through the
    /// relevant profile/path validation API before trusting it.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(64);
        for byte in self.0 {
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0f) as usize] as char);
        }
        output
    }
}

impl fmt::Display for KeyDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl Serialize for KeyDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

/// Domain-separated scope of one selected root within a stable volume
/// namespace. It is intentionally not interchangeable with a path or profile
/// digest.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RootScopeKey(KeyDigest);

impl RootScopeKey {
    pub(crate) const fn new(bytes: [u8; 32]) -> Self {
        Self(KeyDigest::new(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn to_hex(self) -> String {
        self.0.to_hex()
    }
}

impl fmt::Display for RootScopeKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativePathEncoding {
    UnixBytes,
    WindowsUtf16Le,
}

impl NativePathEncoding {
    pub(crate) const fn domain_byte(self) -> u8 {
        match self {
            Self::UnixBytes => 1,
            Self::WindowsUtf16Le => 2,
        }
    }
}

/// A lossless operating-system value. `display` is never used for addressing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NativeValue {
    display: String,
    encoding: NativePathEncoding,
    raw_base64: String,
}

impl NativeValue {
    pub(crate) fn from_raw(raw: &[u8], encoding: NativePathEncoding) -> Self {
        let display = crate::path::display_raw(raw, encoding);
        Self {
            display,
            encoding,
            raw_base64: STANDARD_NO_PAD.encode(raw),
        }
    }

    pub fn display(&self) -> &str {
        &self.display
    }

    pub const fn encoding(&self) -> NativePathEncoding {
        self.encoding
    }

    pub fn raw_base64(&self) -> &str {
        &self.raw_base64
    }

    pub fn decode_raw(&self) -> Result<Vec<u8>, crate::PathError> {
        STANDARD_NO_PAD
            .decode(&self.raw_base64)
            .map_err(|error| crate::PathError::InvalidBase64(error.to_string()))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityStrength {
    Strong,
    Weak,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct NativeUuid([u8; 16]);

impl NativeUuid {
    #[cfg(target_os = "macos")]
    pub(crate) fn from_nonzero(bytes: [u8; 16]) -> Option<Self> {
        bytes.iter().any(|byte| *byte != 0).then_some(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for NativeUuid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                formatter.write_str("-")?;
            }
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VolumeIdentity {
    key: KeyDigest,
    strength: IdentityStrength,
    native_uuid: Option<NativeUuid>,
}

impl VolumeIdentity {
    pub(crate) const fn new(
        key: KeyDigest,
        strength: IdentityStrength,
        native_uuid: Option<NativeUuid>,
    ) -> Self {
        Self {
            key,
            strength,
            native_uuid,
        }
    }

    pub const fn key(&self) -> KeyDigest {
        self.key
    }

    pub const fn strength(&self) -> IdentityStrength {
        self.strength
    }

    pub const fn native_uuid(&self) -> Option<NativeUuid> {
        self.native_uuid
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RootObjectIdentity {
    #[serde(serialize_with = "serialize_u64_decimal")]
    pub device: u64,
    #[serde(serialize_with = "serialize_u64_decimal")]
    pub inode: u64,
    pub generation: u32,
    pub mode: u32,
    pub change_time_seconds: i64,
    pub change_time_nanoseconds: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct FileObjectIdentity {
    #[serde(serialize_with = "serialize_u64_decimal")]
    pub device: u64,
    #[serde(serialize_with = "serialize_u64_decimal")]
    pub inode: u64,
    pub generation: u32,
    pub mode: u32,
    #[serde(serialize_with = "serialize_u64_decimal")]
    pub hard_link_count: u64,
    #[serde(serialize_with = "serialize_u64_decimal")]
    pub size: u64,
    pub birth_time_seconds: i64,
    pub birth_time_nanoseconds: u32,
    pub modified_time_seconds: i64,
    pub modified_time_nanoseconds: u32,
    pub change_time_seconds: i64,
    pub change_time_nanoseconds: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ReadOnlyFormatCapabilities {
    pub case_sensitive: Option<bool>,
    pub case_preserving: Option<bool>,
    pub persistent_object_ids: Option<bool>,
    pub symbolic_links: Option<bool>,
    pub hard_links: Option<bool>,
    /// Actual filesystem timestamp precision when proven by a supported,
    /// read-only platform observation. The reported nanosecond fields in file
    /// identities do not imply one-nanosecond filesystem precision.
    #[serde(serialize_with = "serialize_optional_u64_decimal")]
    pub timestamp_granularity_ns: Option<u64>,
}

/// Write capabilities are intentionally all unknown in this read-only crate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct WriteCapabilities {
    create: Option<bool>,
    no_replace_create: Option<bool>,
    same_volume_rename: Option<bool>,
    file_fsync: Option<bool>,
    parent_directory_fsync: Option<bool>,
    birthtime_write: Option<bool>,
    mtime_write: Option<bool>,
}

impl WriteCapabilities {
    pub const fn unknown() -> Self {
        Self {
            create: None,
            no_replace_create: None,
            same_volume_rename: None,
            file_fsync: None,
            parent_directory_fsync: None,
            birthtime_write: None,
            mtime_write: None,
        }
    }

    pub const fn create(&self) -> Option<bool> {
        self.create
    }

    pub const fn no_replace_create(&self) -> Option<bool> {
        self.no_replace_create
    }

    pub const fn same_volume_rename(&self) -> Option<bool> {
        self.same_volume_rename
    }

    pub const fn file_fsync(&self) -> Option<bool> {
        self.file_fsync
    }

    pub const fn parent_directory_fsync(&self) -> Option<bool> {
        self.parent_directory_fsync
    }

    pub const fn birthtime_write(&self) -> Option<bool> {
        self.birthtime_write
    }

    pub const fn mtime_write(&self) -> Option<bool> {
        self.mtime_write
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct SpaceObservation {
    #[serde(serialize_with = "serialize_optional_u64_decimal")]
    pub block_size: Option<u64>,
    #[serde(serialize_with = "serialize_optional_u64_decimal")]
    pub io_size: Option<u64>,
    #[serde(serialize_with = "serialize_optional_u64_decimal")]
    pub total_bytes: Option<u64>,
    #[serde(serialize_with = "serialize_optional_u64_decimal")]
    pub free_bytes: Option<u64>,
    #[serde(serialize_with = "serialize_optional_u64_decimal")]
    pub available_bytes: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MountObservation {
    mount_point: NativeValue,
    mount_source: NativeValue,
    filesystem_type: NativeValue,
    #[serde(serialize_with = "serialize_u64_decimal")]
    raw_flags: u64,
    mounted_read_only: bool,
    local: Option<bool>,
    space: SpaceObservation,
}

impl MountObservation {
    #[cfg(target_os = "macos")]
    pub(crate) const fn new(
        mount_point: NativeValue,
        mount_source: NativeValue,
        filesystem_type: NativeValue,
        raw_flags: u64,
        mounted_read_only: bool,
        local: Option<bool>,
        space: SpaceObservation,
    ) -> Self {
        Self {
            mount_point,
            mount_source,
            filesystem_type,
            raw_flags,
            mounted_read_only,
            local,
            space,
        }
    }

    pub const fn mount_point(&self) -> &NativeValue {
        &self.mount_point
    }

    pub const fn mount_source(&self) -> &NativeValue {
        &self.mount_source
    }

    pub const fn filesystem_type(&self) -> &NativeValue {
        &self.filesystem_type
    }

    pub const fn raw_flags(&self) -> u64 {
        self.raw_flags
    }

    pub const fn mounted_read_only(&self) -> bool {
        self.mounted_read_only
    }

    pub const fn local(&self) -> Option<bool> {
        self.local
    }

    pub const fn space(&self) -> SpaceObservation {
        self.space
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VolumeObservation {
    identity: VolumeIdentity,
    mount_session_key: KeyDigest,
    mount: MountObservation,
    root_identity: RootObjectIdentity,
    mount_relative_root: NativeValue,
    stable_root_path_key: KeyDigest,
    root_scope_key: RootScopeKey,
    read_only_capabilities: ReadOnlyFormatCapabilities,
    write_capabilities: WriteCapabilities,
    path_semantics: PathSemanticsProfile,
}

pub(crate) struct BoundRootEvidence {
    pub mount_relative_root: NativeValue,
    pub stable_root_path_key: KeyDigest,
    pub root_scope_key: RootScopeKey,
}

impl VolumeObservation {
    pub(crate) fn new(
        identity: VolumeIdentity,
        mount_session_key: KeyDigest,
        mount: MountObservation,
        root_identity: RootObjectIdentity,
        root_evidence: BoundRootEvidence,
        read_only_capabilities: ReadOnlyFormatCapabilities,
        path_semantics: PathSemanticsProfile,
    ) -> Self {
        let BoundRootEvidence {
            mount_relative_root,
            stable_root_path_key,
            root_scope_key,
        } = root_evidence;
        Self {
            identity,
            mount_session_key,
            mount,
            root_identity,
            mount_relative_root,
            stable_root_path_key,
            root_scope_key,
            read_only_capabilities,
            write_capabilities: WriteCapabilities::unknown(),
            path_semantics,
        }
    }

    pub const fn identity(&self) -> &VolumeIdentity {
        &self.identity
    }

    pub const fn mount_session_key(&self) -> KeyDigest {
        self.mount_session_key
    }

    pub const fn mount(&self) -> &MountObservation {
        &self.mount
    }

    pub const fn root_identity(&self) -> RootObjectIdentity {
        self.root_identity
    }

    /// Lossless selected-root address relative to the real mount root.
    pub const fn mount_relative_root(&self) -> &NativeValue {
        &self.mount_relative_root
    }

    pub const fn stable_root_path_key(&self) -> KeyDigest {
        self.stable_root_path_key
    }

    pub const fn root_scope_key(&self) -> RootScopeKey {
        self.root_scope_key
    }

    pub const fn read_only_capabilities(&self) -> ReadOnlyFormatCapabilities {
        self.read_only_capabilities
    }

    pub const fn write_capabilities(&self) -> WriteCapabilities {
        self.write_capabilities
    }

    pub const fn path_semantics(&self) -> &PathSemanticsProfile {
        &self.path_semantics
    }
}

fn serialize_u64_decimal<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_string())
}

fn serialize_optional_u64_decimal<S>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(value) => serializer.serialize_some(&value.to_string()),
        None => serializer.serialize_none(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_u64_evidence_serializes_as_decimal_strings() {
        let root = RootObjectIdentity {
            device: u64::MAX,
            inode: 9_007_199_254_740_993,
            generation: 7,
            mode: 0,
            change_time_seconds: 0,
            change_time_nanoseconds: 0,
        };
        let root_json = serde_json::to_value(root).expect("serialize root identity");
        assert_eq!(root_json["device"], u64::MAX.to_string());
        assert_eq!(root_json["inode"], "9007199254740993");

        let file = FileObjectIdentity {
            device: u64::MAX,
            inode: u64::MAX - 1,
            generation: 7,
            mode: 0,
            hard_link_count: u64::MAX - 2,
            size: u64::MAX - 3,
            birth_time_seconds: 0,
            birth_time_nanoseconds: 0,
            modified_time_seconds: 0,
            modified_time_nanoseconds: 0,
            change_time_seconds: 0,
            change_time_nanoseconds: 0,
        };
        let file_json = serde_json::to_value(file).expect("serialize file identity");
        for field in ["device", "inode", "hard_link_count", "size"] {
            assert!(file_json[field].is_string(), "{field} must be a string");
        }

        let space = SpaceObservation {
            block_size: Some(u64::MAX),
            io_size: Some(u64::MAX - 1),
            total_bytes: Some(u64::MAX - 2),
            free_bytes: Some(u64::MAX - 3),
            available_bytes: None,
        };
        let space_json = serde_json::to_value(space).expect("serialize space observation");
        for field in ["block_size", "io_size", "total_bytes", "free_bytes"] {
            assert!(space_json[field].is_string(), "{field} must be a string");
        }
        assert!(space_json["available_bytes"].is_null());

        let native = NativeValue {
            display: "/".to_owned(),
            encoding: NativePathEncoding::UnixBytes,
            raw_base64: "Lw".to_owned(),
        };
        let mount = MountObservation {
            mount_point: native.clone(),
            mount_source: native.clone(),
            filesystem_type: native,
            raw_flags: u64::MAX,
            mounted_read_only: false,
            local: None,
            space,
        };
        let mount_json = serde_json::to_value(mount).expect("serialize mount observation");
        assert_eq!(mount_json["raw_flags"], u64::MAX.to_string());

        let capabilities = ReadOnlyFormatCapabilities {
            timestamp_granularity_ns: Some(u64::MAX),
            ..ReadOnlyFormatCapabilities::default()
        };
        let capabilities_json =
            serde_json::to_value(capabilities).expect("serialize timestamp granularity");
        assert_eq!(
            capabilities_json["timestamp_granularity_ns"],
            u64::MAX.to_string()
        );
    }

    #[test]
    fn cryptographic_keys_serialize_as_fixed_lowercase_hex() {
        let digest = KeyDigest::new([0xab; 32]);
        let encoded = serde_json::to_value(digest).expect("serialize digest");
        assert_eq!(encoded, "ab".repeat(32));

        let scope = RootScopeKey::new([0xcd; 32]);
        let encoded = serde_json::to_value(scope).expect("serialize root scope");
        assert_eq!(encoded, "cd".repeat(32));
    }
}
