use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::error::PathRefDecodeError;

/// Version of the serialized [`ScanReport`] contract.
pub const REPORT_SCHEMA_VERSION: u32 = 2;

/// Lossless, IPC-safe representation of a native filesystem path.
///
/// `display` is only for presentation. Filesystem operations must reconstruct
/// the native path from `raw_base64` with [`PathRef::to_path_buf`].
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct PathRef {
    pub display: String,
    pub encoding: PathEncoding,
    pub raw_base64: String,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathEncoding {
    UnixBytes,
    WindowsUtf16Le,
    Utf8,
}

impl PathRef {
    pub fn from_path(path: &Path) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            Self {
                display: path.to_string_lossy().into_owned(),
                encoding: PathEncoding::UnixBytes,
                raw_base64: STANDARD_NO_PAD.encode(path.as_os_str().as_bytes()),
            }
        }

        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            let raw: Vec<u8> = path
                .as_os_str()
                .encode_wide()
                .flat_map(u16::to_le_bytes)
                .collect();
            Self {
                display: path.to_string_lossy().into_owned(),
                encoding: PathEncoding::WindowsUtf16Le,
                raw_base64: STANDARD_NO_PAD.encode(raw),
            }
        }

        #[cfg(not(any(unix, windows)))]
        Self {
            display: path.to_string_lossy().into_owned(),
            encoding: PathEncoding::Utf8,
            raw_base64: STANDARD_NO_PAD.encode(path.to_string_lossy().as_bytes()),
        }
    }

    pub fn to_path_buf(&self) -> Result<PathBuf, PathRefDecodeError> {
        let raw = STANDARD_NO_PAD
            .decode(&self.raw_base64)
            .map_err(|error| PathRefDecodeError::InvalidBase64(error.to_string()))?;

        match self.encoding {
            PathEncoding::UnixBytes => {
                #[cfg(unix)]
                {
                    use std::ffi::OsString;
                    use std::os::unix::ffi::OsStringExt;
                    Ok(PathBuf::from(OsString::from_vec(raw)))
                }
                #[cfg(not(unix))]
                {
                    let _ = raw;
                    Err(PathRefDecodeError::UnsupportedEncoding("unix_bytes"))
                }
            }
            PathEncoding::WindowsUtf16Le => {
                if raw.len() % 2 != 0 {
                    return Err(PathRefDecodeError::InvalidUtf16Length);
                }
                #[cfg(windows)]
                {
                    use std::ffi::OsString;
                    use std::os::windows::ffi::OsStringExt;
                    let wide: Vec<u16> = raw
                        .chunks_exact(2)
                        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
                        .collect();
                    Ok(PathBuf::from(OsString::from_wide(&wide)))
                }
                #[cfg(not(windows))]
                {
                    Err(PathRefDecodeError::UnsupportedEncoding("windows_utf16_le"))
                }
            }
            PathEncoding::Utf8 => String::from_utf8(raw)
                .map(PathBuf::from)
                .map_err(|error| PathRefDecodeError::InvalidUtf8(error.to_string())),
        }
    }
}

impl From<&Path> for PathRef {
    fn from(path: &Path) -> Self {
        Self::from_path(path)
    }
}

impl From<&PathBuf> for PathRef {
    fn from(path: &PathBuf) -> Self {
        Self::from_path(path)
    }
}

/// A filesystem timestamp represented without timezone conversion.
///
/// `seconds` is the floor number of seconds from the Unix epoch and
/// `nanoseconds` is always in `0..1_000_000_000`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct FileTimestamp {
    pub seconds: i64,
    pub nanoseconds: u32,
}

impl FileTimestamp {
    pub(crate) fn from_system_time(value: SystemTime) -> Option<Self> {
        match value.duration_since(UNIX_EPOCH) {
            Ok(duration) => Some(Self {
                seconds: i64::try_from(duration.as_secs()).ok()?,
                nanoseconds: duration.subsec_nanos(),
            }),
            Err(error) => {
                let duration = error.duration();
                let seconds = i64::try_from(duration.as_secs()).ok()?;
                let nanoseconds = duration.subsec_nanos();
                if nanoseconds == 0 {
                    Some(Self {
                        seconds: seconds.checked_neg()?,
                        nanoseconds: 0,
                    })
                } else {
                    Some(Self {
                        seconds: seconds.checked_neg()?.checked_sub(1)?,
                        nanoseconds: 1_000_000_000 - nanoseconds,
                    })
                }
            }
        }
    }
}

/// Best-effort physical identity of a file on a mounted volume.
///
/// It is present on Unix platforms and is useful for recognizing hard-link
/// aliases. It must not be treated as durable across remounts.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct FileId {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaKind {
    Image,
    RawImage,
    Video,
}

impl MediaKind {
    pub(crate) fn from_extension(extension: &str) -> Option<Self> {
        match extension {
            "jpg" | "jpeg" | "jpe" | "heic" | "heif" | "png" | "gif" | "webp" | "avif" | "tif"
            | "tiff" | "bmp" => Some(Self::Image),
            "dng" | "cr2" | "cr3" | "nef" | "nrw" | "arw" | "srf" | "sr2" | "raf" | "orf"
            | "rw2" | "pef" | "x3f" | "raw" => Some(Self::RawImage),
            "mov" | "mp4" | "m4v" | "3gp" | "3g2" | "avi" | "mkv" | "mts" | "m2ts" | "webm" => {
                Some(Self::Video)
            }
            _ => None,
        }
    }
}

/// Configuration for a read-only scan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanOptions {
    /// Number of bytes read at each of the beginning, middle, and end sample.
    pub sample_bytes: u64,
    /// Streaming buffer used for full hashing and byte-for-byte comparison.
    pub read_buffer_bytes: u64,
    /// Do not descend into a nested mount point by default.
    pub stay_on_filesystem: bool,
    /// Lowercase media-payload extensions considered by M0. Sidecars such as
    /// AAE, XMP, JSON, and THM are intentionally not enumerated or linked yet.
    pub media_extensions: BTreeSet<String>,
    /// Case-insensitive directory names skipped without opening.
    pub excluded_directory_names: BTreeSet<String>,
    /// Case-insensitive directory-name prefixes skipped without opening.
    pub excluded_directory_prefixes: BTreeSet<String>,
    /// Case-insensitive directory-name suffixes skipped without opening.
    pub excluded_directory_suffixes: BTreeSet<String>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        const EXTENSIONS: &[&str] = &[
            "3g2", "3gp", "arw", "avif", "avi", "bmp", "cr2", "cr3", "dng", "gif", "heic", "heif",
            "jpe", "jpeg", "jpg", "m2ts", "m4v", "mkv", "mov", "mp4", "mts", "nef", "nrw", "orf",
            "pef", "png", "raf", "raw", "rw2", "sr2", "srf", "tif", "tiff", "webm", "webp", "x3f",
        ];
        const EXCLUDED_NAMES: &[&str] = &[
            "$recycle.bin",
            ".appledb",
            ".appledesktop",
            ".appledouble",
            ".com.apple.timemachine.localsnapshots",
            ".documentrevisions-v100",
            ".fseventsd",
            ".guiying",
            ".guiying-quarantine",
            ".mobilebackups",
            ".spotlight-v100",
            ".temporaryitems",
            ".trash",
            ".trashes",
            "lost+found",
            "network trash folder",
            "recycler",
            "system volume information",
            "temporary items",
        ];

        Self {
            sample_bytes: 64 * 1024,
            read_buffer_bytes: 1024 * 1024,
            stay_on_filesystem: true,
            media_extensions: EXTENSIONS.iter().map(|value| (*value).to_owned()).collect(),
            excluded_directory_names: EXCLUDED_NAMES
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            excluded_directory_prefixes: [".trash-"].into_iter().map(str::to_owned).collect(),
            excluded_directory_suffixes: [".photoslibrary"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        }
    }
}

impl ScanOptions {
    pub(crate) fn media_kind(&self, path: &std::path::Path) -> Option<MediaKind> {
        let extension = path.extension()?.to_str()?.to_ascii_lowercase();
        if !self.media_extensions.contains(&extension) {
            return None;
        }
        MediaKind::from_extension(&extension).or(Some(MediaKind::Image))
    }

    pub(crate) fn directory_exclusion(&self, path: &Path) -> Option<String> {
        let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
        if self.excluded_directory_names.contains(&name) {
            return Some(format!("directory name `{name}` is excluded"));
        }
        if let Some(prefix) = self
            .excluded_directory_prefixes
            .iter()
            .find(|prefix| name.starts_with(prefix.as_str()))
        {
            return Some(format!("directory prefix `{prefix}` is excluded"));
        }
        self.excluded_directory_suffixes
            .iter()
            .find(|suffix| name.ends_with(suffix.as_str()))
            .map(|suffix| format!("directory suffix `{suffix}` is excluded"))
    }
}

/// A media file as observed during scanning.
///
/// A missing fingerprint/hash means that the file did not reach that pipeline
/// stage (for example, its size was unique), not that its content was empty.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FileRecord {
    pub path: PathRef,
    pub media_kind: MediaKind,
    pub size: u64,
    pub modified: Option<FileTimestamp>,
    pub created: Option<FileTimestamp>,
    pub file_id: Option<FileId>,
    pub hard_link_count: Option<u64>,
    pub sample_fingerprint: Option<String>,
    pub content_hash: Option<String>,
}

/// A group whose members passed size, sampled fingerprint, full BLAKE3, and
/// byte-for-byte comparison while remaining bound to their scanned identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DuplicateGroup {
    pub id: String,
    pub content_hash: String,
    pub size: u64,
    pub files: Vec<FileRecord>,
    pub proof: DuplicateProof,
    /// Number of distinct physical file identities when they are available.
    pub independent_file_count: u64,
    /// Upper-bound logical estimate; APFS clones and sparse allocation can make
    /// actual reclaimed disk blocks lower.
    pub logical_reclaimable_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DuplicateProof {
    ByteForByte,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanIssueCode {
    SymlinkSkipped,
    CrossFilesystemSkipped,
    DirectoryIdentityAlreadyVisited,
    DirectoryExcluded,
    MetadataUnreadable,
    DirectoryUnreadable,
    UnsupportedFileType,
    FileUnreadable,
    ChangedDuringScan,
    ExactVerificationFailed,
    HashCollisionDetected,
    RootChangedDuringScan,
}

/// A deliberate skip, recoverable per-entry problem, or terminal root-session
/// problem. Callers must inspect [`ScanReport::status`] before using results.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScanIssue {
    pub code: ScanIssueCode,
    pub path: PathRef,
    pub detail: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScanStats {
    pub entries_seen: u64,
    pub media_files: u64,
    pub non_media_files_skipped: u64,
    pub symlinks_skipped: u64,
    pub special_files_skipped: u64,
    pub cross_filesystem_directories_skipped: u64,
    pub cross_filesystem_files_skipped: u64,
    pub directory_identity_revisits_skipped: u64,
    pub excluded_directories_skipped: u64,
    pub files_sampled: u64,
    pub files_fully_hashed: u64,
    pub bytes_sampled: u64,
    pub bytes_fully_hashed: u64,
    pub exact_comparisons: u64,
    pub bytes_exactly_compared: u64,
    pub duplicate_groups: u64,
    pub duplicate_files: u64,
    pub logical_reclaimable_bytes: u64,
    pub issues: u64,
}

/// Stable, versioned, deterministically ordered result of a scan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema_version: u32,
    pub roots: Vec<PathRef>,
    pub files: Vec<FileRecord>,
    pub duplicate_groups: Vec<DuplicateGroup>,
    pub issues: Vec<ScanIssue>,
    pub stats: ScanStats,
    pub status: ScanStatus,
    pub cancelled: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Complete,
    Partial,
    Cancelled,
    Interrupted,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgressStage {
    Enumerating,
    Sampling,
    FullHashing,
    ExactComparing,
    Complete,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScanProgress {
    pub stage: ProgressStage,
    pub completed: u64,
    pub total: Option<u64>,
    pub current_path: Option<PathRef>,
}
