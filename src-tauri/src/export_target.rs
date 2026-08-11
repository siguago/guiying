#[cfg(unix)]
use std::ffi::CString;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use guiying_store::{
    HistoryExportProjection, HistoryExportRecord, HistoryExportRequest, HistoryExportScope,
    ScanHistoryContext, StoreError,
};
use serde::Serialize;

const EXPORT_SCHEMA: &str = "guiying.history_export.v1";
const LOGICAL_DIGEST_DOMAIN: &[u8] = b"guiying.history-export.logical-records.v1\0";
const DECIMAL_ENCODING: &str = "canonical_base10_string";
const RECORD_ORDER: &str = "summary,duplicate_group,duplicate_member,scan_issue";
#[cfg(unix)]
const TEMP_NAME_ATTEMPTS: usize = 8;
#[cfg(unix)]
const TEMP_NAME_PREFIX: &str = ".guiying-export-";
const CSV_HEADER: &[&str] = &[
    "schema_version",
    "profile",
    "section",
    "sequence",
    "record_json",
];
const CSV_SCHEMA_VERSION: &str = EXPORT_SCHEMA;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExportFormat {
    Json,
    Csv,
}

impl ExportFormat {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "json" => Some(Self::Json),
            "csv" => Some(Self::Csv),
            _ => None,
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Csv => "csv",
        }
    }

    pub(crate) const fn extension(self) -> &'static str {
        self.as_str()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExportLimits {
    pub(crate) max_output_bytes: u64,
    pub(crate) max_records: u32,
    pub(crate) max_duration: Duration,
}

impl ExportLimits {
    pub(crate) const fn for_scope(scope: HistoryExportScope) -> Self {
        match scope {
            HistoryExportScope::Summary => Self {
                max_output_bytes: 2 * 1024 * 1024,
                max_records: 1,
                max_duration: Duration::from_secs(5),
            },
            HistoryExportScope::CompleteEvidence => Self {
                max_output_bytes: 256 * 1024 * 1024,
                max_records: 250_000,
                max_duration: Duration::from_secs(60),
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExportArtifact {
    pub(crate) file_name: String,
    pub(crate) bytes_written: u64,
    pub(crate) record_count: u32,
    pub(crate) logical_digest: String,
    pub(crate) publication_status: &'static str,
    pub(crate) warning_code: Option<&'static str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExportTargetError {
    InvalidSelection,
    #[cfg(not(unix))]
    UnsupportedPlatform,
    TargetExists,
    UnsafeTarget,
    RandomUnavailable,
    OpenFailed,
    WriteFailed,
    OutputLimitExceeded,
    Cancelled,
    DeadlineExceeded,
    StoreFailed,
    EncodeFailed,
    PublishFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommitState {
    Open,
    Committed,
}

pub(crate) struct ExportCancellation {
    cancelled: AtomicBool,
    commit_state: StdMutex<CommitState>,
}

impl ExportCancellation {
    pub(crate) fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            commit_state: StdMutex::new(CommitState::Open),
        }
    }

    pub(crate) fn cancel(&self) -> bool {
        let state = match self.commit_state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        if *state == CommitState::Committed {
            return false;
        }
        !self.cancelled.swap(true, Ordering::AcqRel)
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    fn commit_link(
        &self,
        operation: impl FnOnce() -> Result<LinkCommit, ExportTargetError>,
    ) -> Result<LinkCommit, ExportTargetError> {
        let mut state = match self.commit_state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        if *state != CommitState::Open {
            return Err(ExportTargetError::PublishFailed);
        }
        if self.cancelled.load(Ordering::Acquire) {
            return Err(ExportTargetError::Cancelled);
        }
        let committed = operation()?;
        *state = CommitState::Committed;
        Ok(committed)
    }
}

pub(crate) struct BoundExportTarget {
    #[cfg(unix)]
    parent: Arc<DirectoryHandle>,
    #[cfg(unix)]
    file_name: CString,
    display_file_name: String,
}

impl std::fmt::Debug for BoundExportTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BoundExportTarget")
            .field("parent", &"<redacted>")
            .field("file_name", &self.display_file_name)
            .finish_non_exhaustive()
    }
}

impl BoundExportTarget {
    pub(crate) fn bind(selected: PathBuf, format: ExportFormat) -> Result<Self, ExportTargetError> {
        if !selected.is_absolute() {
            return Err(ExportTargetError::InvalidSelection);
        }
        let selected_name = selected
            .file_name()
            .and_then(safe_display_file_name)
            .ok_or(ExportTargetError::InvalidSelection)?
            .to_owned();
        if !has_exact_extension(&selected_name, format.extension()) {
            return Err(ExportTargetError::InvalidSelection);
        }
        #[cfg(unix)]
        {
            if !selected_has_exact_final_name(&selected, &selected_name) {
                return Err(ExportTargetError::InvalidSelection);
            }
            let selected_parent = selected
                .parent()
                .ok_or(ExportTargetError::InvalidSelection)?;
            let canonical_parent = selected_parent
                .canonicalize()
                .map_err(|_| ExportTargetError::UnsafeTarget)?;
            let parent = Arc::new(DirectoryHandle::open(&canonical_parent)?);
            let file_name = c_string(
                selected
                    .file_name()
                    .ok_or(ExportTargetError::InvalidSelection)?,
            )?;
            parent.ensure_absent(&file_name)?;
            Ok(Self {
                parent,
                file_name,
                display_file_name: selected_name,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = (selected, selected_name, format);
            Err(ExportTargetError::UnsupportedPlatform)
        }
    }

    pub(crate) fn display_file_name(&self) -> &str {
        &self.display_file_name
    }

    fn create_temp(&self) -> Result<OwnedTemp, ExportTargetError> {
        #[cfg(unix)]
        {
            self.parent.revalidate()?;
            self.parent.ensure_absent(&self.file_name)?;
            for _ in 0..TEMP_NAME_ATTEMPTS {
                let mut entropy = [0_u8; 24];
                getrandom::fill(&mut entropy).map_err(|_| ExportTargetError::RandomUnavailable)?;
                let name = CString::new(format!("{TEMP_NAME_PREFIX}{}.tmp", hex(&entropy)))
                    .map_err(|_| ExportTargetError::RandomUnavailable)?;
                let file = match self.parent.create_new_private(&name) {
                    Ok(file) => file,
                    Err(CreateAtError::Exists) => continue,
                    Err(CreateAtError::Failed) => return Err(ExportTargetError::OpenFailed),
                };
                secure_private_file(&file)?;
                let identity = verify_temp_identity(&file, &self.parent, &name)?;
                return Ok(OwnedTemp {
                    file: Some(file),
                    parent: Arc::clone(&self.parent),
                    name,
                    identity,
                });
            }
            Err(ExportTargetError::RandomUnavailable)
        }
        #[cfg(not(unix))]
        {
            Err(ExportTargetError::UnsupportedPlatform)
        }
    }

    fn commit_link(&self, temp: &mut OwnedTemp) -> Result<LinkCommit, ExportTargetError> {
        #[cfg(unix)]
        {
            self.parent.revalidate()?;
            self.parent.ensure_absent(&self.file_name)?;
            temp.revalidate(self)?;
            self.parent.link_no_replace(&temp.name, &self.file_name)?;
            Ok(LinkCommit {
                identity_verified: self
                    .parent
                    .entry_matches_identity(&self.file_name, &temp.identity),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = temp;
            Err(ExportTargetError::UnsupportedPlatform)
        }
    }

    fn finish_committed(&self, temp: &mut OwnedTemp, link: LinkCommit) -> PublicationOutcome {
        #[cfg(unix)]
        {
            let cleanup_failed = temp.remove_owned_name().is_err();
            let directory_sync_failed = self.parent.sync().is_err();
            let target_revalidated = self.parent.revalidate().is_ok()
                && self
                    .parent
                    .entry_matches_identity(&self.file_name, &temp.identity);
            publication_outcome(
                link.identity_verified,
                target_revalidated,
                cleanup_failed,
                directory_sync_failed,
            )
        }
        #[cfg(not(unix))]
        {
            let _ = (temp, link);
            PublicationOutcome::CommitUncertain("TARGET_REVALIDATION_UNCERTAIN")
        }
    }
}

#[cfg_attr(not(unix), allow(dead_code))]
fn publication_outcome(
    link_identity_verified: bool,
    target_revalidated: bool,
    cleanup_failed: bool,
    directory_sync_failed: bool,
) -> PublicationOutcome {
    if !target_revalidated {
        return PublicationOutcome::CommitUncertain("TARGET_REVALIDATION_UNCERTAIN");
    }
    if !link_identity_verified {
        return PublicationOutcome::CommitUncertain("TARGET_IDENTITY_UNCERTAIN");
    }
    match (cleanup_failed, directory_sync_failed) {
        (false, false) => PublicationOutcome::Committed,
        (true, false) => PublicationOutcome::CommittedWithWarning("TEMP_CLEANUP_DEFERRED"),
        (false, true) => PublicationOutcome::CommittedWithWarning("DIRECTORY_SYNC_UNAVAILABLE"),
        (true, true) => {
            PublicationOutcome::CommittedWithWarning("TEMP_CLEANUP_AND_DIRECTORY_SYNC_UNAVAILABLE")
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(unix), allow(dead_code))]
struct LinkCommit {
    identity_verified: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicationOutcome {
    Committed,
    CommittedWithWarning(&'static str),
    CommitUncertain(&'static str),
}

impl PublicationOutcome {
    const fn status(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::CommittedWithWarning(_) => "committed_with_warning",
            Self::CommitUncertain(_) => "commit_uncertain",
        }
    }

    const fn warning_code(self) -> Option<&'static str> {
        match self {
            Self::Committed => None,
            Self::CommittedWithWarning(code) | Self::CommitUncertain(code) => Some(code),
        }
    }
}

fn safe_display_file_name(value: &OsStr) -> Option<&str> {
    let value = value.to_str()?;
    let byte_length = value.len();
    if byte_length == 0
        || byte_length > 1024
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
        || value.chars().any(|character| {
            let code_point = u32::from(character);
            code_point <= 31 || (127..=159).contains(&code_point)
        })
    {
        None
    } else {
        Some(value)
    }
}

fn has_exact_extension(file_name: &str, extension: &str) -> bool {
    file_name
        .rfind('.')
        .is_some_and(|separator| separator > 0 && &file_name[separator + 1..] == extension)
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl FileIdentity {
    fn from_stat(stat: &libc::stat) -> Self {
        Self {
            device: stat.st_dev as u64,
            inode: stat.st_ino,
        }
    }
}

struct OwnedTemp {
    file: Option<File>,
    #[cfg(unix)]
    parent: Arc<DirectoryHandle>,
    #[cfg(unix)]
    name: CString,
    #[cfg(unix)]
    identity: FileIdentity,
}

impl OwnedTemp {
    fn file_mut(&mut self) -> Result<&mut File, ExportTargetError> {
        self.file.as_mut().ok_or(ExportTargetError::WriteFailed)
    }

    fn flush_and_sync(&mut self) -> Result<(), ExportTargetError> {
        let file = self.file_mut()?;
        file.flush().map_err(|_| ExportTargetError::WriteFailed)?;
        #[cfg(unix)]
        {
            sync_fd(file.as_raw_fd()).map_err(|_| ExportTargetError::WriteFailed)
        }
        #[cfg(not(unix))]
        {
            Err(ExportTargetError::UnsupportedPlatform)
        }
    }

    fn revalidate(&self, target: &BoundExportTarget) -> Result<(), ExportTargetError> {
        #[cfg(unix)]
        {
            if !Arc::ptr_eq(&self.parent, &target.parent) {
                return Err(ExportTargetError::UnsafeTarget);
            }
            let file = self.file.as_ref().ok_or(ExportTargetError::UnsafeTarget)?;
            let identity = verify_temp_identity(file, &self.parent, &self.name)?;
            if identity != self.identity {
                return Err(ExportTargetError::UnsafeTarget);
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = target;
            Err(ExportTargetError::UnsupportedPlatform)
        }
    }

    #[cfg(unix)]
    fn remove_owned_name(&mut self) -> Result<(), ExportTargetError> {
        if !self
            .parent
            .entry_matches_identity(&self.name, &self.identity)
        {
            return Err(ExportTargetError::UnsafeTarget);
        }
        self.parent.unlink(&self.name)
    }
}

impl Drop for OwnedTemp {
    fn drop(&mut self) {
        self.file.take();
        #[cfg(unix)]
        if self
            .parent
            .entry_matches_identity(&self.name, &self.identity)
        {
            let _ignored = self.parent.unlink(&self.name);
        }
    }
}

#[cfg(unix)]
fn verify_temp_identity(
    file: &File,
    parent: &DirectoryHandle,
    name: &CString,
) -> Result<FileIdentity, ExportTargetError> {
    let handle_stat = fstat(file.as_raw_fd())?;
    let name_stat = parent
        .stat_entry(name)?
        .ok_or(ExportTargetError::UnsafeTarget)?;
    if !is_regular_file(&handle_stat) || !is_regular_file(&name_stat) {
        return Err(ExportTargetError::UnsafeTarget);
    }
    let handle_identity = FileIdentity::from_stat(&handle_stat);
    let path_identity = FileIdentity::from_stat(&name_stat);
    if handle_identity != path_identity {
        return Err(ExportTargetError::UnsafeTarget);
    }
    verify_private_temp_stat(&handle_stat, &parent.identity)?;
    Ok(handle_identity)
}

#[cfg(unix)]
fn secure_private_file(file: &File) -> Result<(), ExportTargetError> {
    // SAFETY: the descriptor is owned and valid for the duration of the call.
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } == 0 {
        Ok(())
    } else {
        Err(ExportTargetError::UnsafeTarget)
    }
}

#[cfg(unix)]
fn verify_private_temp_stat(
    stat: &libc::stat,
    parent_identity: &FileIdentity,
) -> Result<(), ExportTargetError> {
    // SAFETY: geteuid has no preconditions and does not dereference memory.
    let effective_uid = unsafe { libc::geteuid() };
    if stat.st_dev as u64 != parent_identity.device
        || stat.st_nlink != 1
        || stat.st_uid != effective_uid
        || stat.st_mode & 0o777 != 0o600
    {
        return Err(ExportTargetError::UnsafeTarget);
    }
    Ok(())
}

#[cfg(unix)]
fn c_string(value: &OsStr) -> Result<CString, ExportTargetError> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(value.as_bytes()).map_err(|_| ExportTargetError::InvalidSelection)
}

#[cfg(unix)]
fn selected_has_exact_final_name(selected: &Path, display_file_name: &str) -> bool {
    use std::os::unix::ffi::OsStrExt;
    selected
        .as_os_str()
        .as_bytes()
        .rsplit(|byte| *byte == b'/')
        .next()
        .is_some_and(|name| name == display_file_name.as_bytes())
}

#[cfg(unix)]
fn fstat(fd: RawFd) -> Result<libc::stat, ExportTargetError> {
    // SAFETY: zero is a valid initial byte pattern for the platform stat output buffer.
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    // SAFETY: fd is live and stat points to writable storage of the correct type.
    if unsafe { libc::fstat(fd, &raw mut stat) } == 0 {
        Ok(stat)
    } else {
        Err(ExportTargetError::UnsafeTarget)
    }
}

#[cfg(unix)]
fn sync_fd(fd: RawFd) -> io::Result<()> {
    // SAFETY: fd is live for the duration of the call.
    if unsafe { libc::fsync(fd) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn is_directory(stat: &libc::stat) -> bool {
    stat.st_mode & libc::S_IFMT == libc::S_IFDIR
}

#[cfg(unix)]
fn is_regular_file(stat: &libc::stat) -> bool {
    stat.st_mode & libc::S_IFMT == libc::S_IFREG
}

#[cfg(unix)]
enum CreateAtError {
    Exists,
    Failed,
}

#[cfg(unix)]
struct DirectoryHandle {
    file: File,
    identity: FileIdentity,
}

#[cfg(unix)]
impl DirectoryHandle {
    fn open(path: &Path) -> Result<Self, ExportTargetError> {
        let path = c_string(path.as_os_str()).map_err(|_| ExportTargetError::UnsafeTarget)?;
        // SAFETY: path is NUL-terminated; flags request a non-followed directory handle.
        let descriptor = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            )
        };
        if descriptor < 0 {
            return Err(ExportTargetError::UnsafeTarget);
        }
        // SAFETY: descriptor was returned uniquely by open and ownership transfers to File.
        let file = unsafe { File::from_raw_fd(descriptor) };
        let stat = fstat(file.as_raw_fd())?;
        if !is_directory(&stat) {
            return Err(ExportTargetError::UnsafeTarget);
        }
        Ok(Self {
            file,
            identity: FileIdentity::from_stat(&stat),
        })
    }

    fn descriptor(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    fn revalidate(&self) -> Result<(), ExportTargetError> {
        let stat = fstat(self.descriptor())?;
        if !is_directory(&stat) || FileIdentity::from_stat(&stat) != self.identity {
            return Err(ExportTargetError::UnsafeTarget);
        }
        Ok(())
    }

    fn stat_entry(&self, name: &CString) -> Result<Option<libc::stat>, ExportTargetError> {
        // SAFETY: zero is a valid initial byte pattern for the platform stat output buffer.
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        // SAFETY: the directory descriptor and NUL-terminated relative name are live; the
        // output pointer is valid and AT_SYMLINK_NOFOLLOW preserves entry identity.
        if unsafe {
            libc::fstatat(
                self.descriptor(),
                name.as_ptr(),
                &raw mut stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0
        {
            return Ok(Some(stat));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err(ExportTargetError::UnsafeTarget)
        }
    }

    fn ensure_absent(&self, name: &CString) -> Result<(), ExportTargetError> {
        match self.stat_entry(name)? {
            None => Ok(()),
            Some(_) => Err(ExportTargetError::TargetExists),
        }
    }

    fn create_new_private(&self, name: &CString) -> Result<File, CreateAtError> {
        // SAFETY: descriptor and NUL-terminated relative name are live; the mode is supplied
        // because O_CREAT is set, and O_EXCL/O_NOFOLLOW prevent replacement or traversal.
        let descriptor = unsafe {
            libc::openat(
                self.descriptor(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if descriptor >= 0 {
            // SAFETY: descriptor was returned uniquely by openat and ownership transfers to File.
            return Ok(unsafe { File::from_raw_fd(descriptor) });
        }
        if io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST) {
            Err(CreateAtError::Exists)
        } else {
            Err(CreateAtError::Failed)
        }
    }

    fn link_no_replace(&self, source: &CString, target: &CString) -> Result<(), ExportTargetError> {
        // SAFETY: both relative names are NUL-terminated and the same live directory descriptor
        // scopes source and destination. linkat never replaces an existing target.
        if unsafe {
            libc::linkat(
                self.descriptor(),
                source.as_ptr(),
                self.descriptor(),
                target.as_ptr(),
                0,
            )
        } == 0
        {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EEXIST) {
            Err(ExportTargetError::TargetExists)
        } else {
            Err(ExportTargetError::PublishFailed)
        }
    }

    fn unlink(&self, name: &CString) -> Result<(), ExportTargetError> {
        // SAFETY: descriptor and NUL-terminated relative name are live; flags=0 removes a file.
        if unsafe { libc::unlinkat(self.descriptor(), name.as_ptr(), 0) } == 0 {
            Ok(())
        } else {
            Err(ExportTargetError::PublishFailed)
        }
    }

    fn entry_matches_identity(&self, name: &CString, identity: &FileIdentity) -> bool {
        self.stat_entry(name)
            .ok()
            .flatten()
            .filter(is_regular_file)
            .is_some_and(|stat| FileIdentity::from_stat(&stat).eq(identity))
    }

    fn sync(&self) -> Result<(), ExportTargetError> {
        sync_fd(self.descriptor()).map_err(|_| ExportTargetError::PublishFailed)
    }
}

struct CountingWriter<W> {
    inner: W,
    written: u64,
    limit: u64,
    limit_exceeded: bool,
}

impl<W> CountingWriter<W> {
    fn new(inner: W, limit: u64) -> Self {
        Self {
            inner,
            written: 0,
            limit,
            limit_exceeded: false,
        }
    }

    const fn written(&self) -> u64 {
        self.written
    }

    const fn limit_exceeded(&self) -> bool {
        self.limit_exceeded
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let requested = u64::try_from(buffer.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::StorageFull, "export output limit exceeded")
        })?;
        if self
            .written
            .checked_add(requested)
            .is_none_or(|next| next > self.limit)
        {
            self.limit_exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "export output limit exceeded",
            ));
        }
        let count = self.inner.write(buffer)?;
        self.written = self
            .written
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("export byte count overflow"))?;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportManifest<'a> {
    schema: &'static str,
    format: &'static str,
    scope: &'a str,
    path_policy: &'a str,
    decimal_encoding: &'static str,
    record_order: &'static str,
    filesystem_authority: &'static str,
    metadata_payloads: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportIntegrity<'a> {
    digest_algorithm: &'static str,
    logical_digest: &'a str,
    record_count: String,
}

struct ExportEncoder<W> {
    writer: CountingWriter<W>,
    format: ExportFormat,
    scope: &'static str,
    projection: &'static str,
    profile: &'static str,
    expected_records: u32,
    record_count: u32,
    first_json_record: bool,
    hasher: blake3::Hasher,
}

impl<W: Write> ExportEncoder<W> {
    fn begin(
        inner: W,
        format: ExportFormat,
        request: HistoryExportRequest,
        expected_records: u32,
        output_limit: u64,
    ) -> Result<Self, ExportTargetError> {
        let scope = export_scope_name(request.scope());
        let projection = export_projection_name(request.projection());
        let profile = export_profile_name(request.scope(), request.projection());
        let mut hasher = blake3::Hasher::new();
        hasher.update(LOGICAL_DIGEST_DOMAIN);
        hash_length_prefixed(&mut hasher, scope.as_bytes());
        hash_length_prefixed(&mut hasher, projection.as_bytes());
        hash_length_prefixed(&mut hasher, &expected_records.to_le_bytes());
        let mut encoder = Self {
            writer: CountingWriter::new(inner, output_limit),
            format,
            scope,
            projection,
            profile,
            expected_records,
            record_count: 0,
            first_json_record: true,
            hasher,
        };
        encoder.write_manifest()?;
        Ok(encoder)
    }

    fn write_manifest(&mut self) -> Result<(), ExportTargetError> {
        let manifest = ExportManifest {
            schema: EXPORT_SCHEMA,
            format: self.format.as_str(),
            scope: self.scope,
            path_policy: self.projection,
            decimal_encoding: DECIMAL_ENCODING,
            record_order: RECORD_ORDER,
            filesystem_authority: "omitted",
            metadata_payloads: "omitted",
        };
        let manifest_json =
            serde_json::to_vec(&manifest).map_err(|_| ExportTargetError::EncodeFailed)?;
        let manifest_json =
            std::str::from_utf8(&manifest_json).map_err(|_| ExportTargetError::EncodeFailed)?;
        match self.format {
            ExportFormat::Json => {
                self.write_all(b"{\"manifest\":")?;
                self.write_all(manifest_json.as_bytes())?;
                self.write_all(b",\"records\":[")
            }
            ExportFormat::Csv => {
                write_csv_row(&mut self.writer, CSV_HEADER).map_err(|_| self.write_error())?;
                write_csv_row(
                    &mut self.writer,
                    &[
                        CSV_SCHEMA_VERSION,
                        self.profile,
                        "manifest",
                        "",
                        manifest_json,
                    ],
                )
                .map_err(|_| self.write_error())
            }
        }
    }

    fn write_record(&mut self, record: &HistoryExportRecord) -> Result<(), ExportTargetError> {
        if self.record_count >= self.expected_records {
            return Err(ExportTargetError::StoreFailed);
        }
        let canonical = serde_json::to_vec(record).map_err(|_| ExportTargetError::EncodeFailed)?;
        hash_length_prefixed(&mut self.hasher, &canonical);
        match self.format {
            ExportFormat::Json => {
                if !self.first_json_record {
                    self.write_all(b",")?;
                }
                self.first_json_record = false;
                self.write_all(&canonical)?;
            }
            ExportFormat::Csv => {
                let record_json =
                    std::str::from_utf8(&canonical).map_err(|_| ExportTargetError::EncodeFailed)?;
                let sequence = self.record_count.to_string();
                write_csv_row(
                    &mut self.writer,
                    &[
                        CSV_SCHEMA_VERSION,
                        self.profile,
                        "record",
                        &sequence,
                        record_json,
                    ],
                )
                .map_err(|_| self.write_error())?;
            }
        }
        self.record_count = self
            .record_count
            .checked_add(1)
            .ok_or(ExportTargetError::OutputLimitExceeded)?;
        Ok(())
    }

    fn finish(mut self) -> Result<EncoderResult, ExportTargetError> {
        if self.record_count != self.expected_records {
            return Err(ExportTargetError::StoreFailed);
        }
        hash_length_prefixed(&mut self.hasher, &self.record_count.to_le_bytes());
        let digest = self.hasher.finalize().to_hex().to_string();
        let integrity = ExportIntegrity {
            digest_algorithm: "blake3",
            logical_digest: &digest,
            record_count: self.record_count.to_string(),
        };
        match self.format {
            ExportFormat::Json => {
                self.write_all(b"],\"integrity\":")?;
                self.write_json_value(&integrity)?;
                self.write_all(b"}\n")?;
            }
            ExportFormat::Csv => {
                let integrity_json =
                    serde_json::to_vec(&integrity).map_err(|_| ExportTargetError::EncodeFailed)?;
                let integrity_json = std::str::from_utf8(&integrity_json)
                    .map_err(|_| ExportTargetError::EncodeFailed)?;
                write_csv_row(
                    &mut self.writer,
                    &[
                        CSV_SCHEMA_VERSION,
                        self.profile,
                        "integrity",
                        "",
                        integrity_json,
                    ],
                )
                .map_err(|_| self.write_error())?;
            }
        }
        self.writer.flush().map_err(|_| self.write_error())?;
        Ok(EncoderResult {
            bytes_written: self.writer.written(),
            record_count: self.record_count,
            logical_digest: digest,
        })
    }

    fn write_json_value(&mut self, value: &impl Serialize) -> Result<(), ExportTargetError> {
        serde_json::to_writer(&mut self.writer, value).map_err(|_| self.write_error())
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), ExportTargetError> {
        self.writer.write_all(bytes).map_err(|_| self.write_error())
    }

    fn write_error(&self) -> ExportTargetError {
        if self.writer.limit_exceeded() {
            ExportTargetError::OutputLimitExceeded
        } else {
            ExportTargetError::WriteFailed
        }
    }
}

struct EncoderResult {
    bytes_written: u64,
    record_count: u32,
    logical_digest: String,
}

fn write_csv_row<W: Write>(writer: &mut W, fields: &[&str]) -> io::Result<()> {
    for (index, field) in fields.iter().enumerate() {
        if index != 0 {
            writer.write_all(b",")?;
        }
        write_csv_field(writer, field.as_bytes())?;
    }
    writer.write_all(b"\r\n")
}

fn write_csv_field<W: Write>(writer: &mut W, value: &[u8]) -> io::Result<()> {
    let quoted = value
        .iter()
        .any(|byte| matches!(byte, b',' | b'"' | b'\r' | b'\n'));
    if !quoted {
        return writer.write_all(value);
    }
    writer.write_all(b"\"")?;
    for byte in value {
        if *byte == b'"' {
            writer.write_all(b"\"\"")?;
        } else {
            writer.write_all(std::slice::from_ref(byte))?;
        }
    }
    writer.write_all(b"\"")
}

fn export_scope_name(scope: HistoryExportScope) -> &'static str {
    match scope {
        HistoryExportScope::Summary => "summary",
        HistoryExportScope::CompleteEvidence => "complete_evidence",
    }
}

fn export_projection_name(projection: HistoryExportProjection) -> &'static str {
    match projection {
        HistoryExportProjection::Redacted => "redacted",
        HistoryExportProjection::Display => "display",
    }
}

fn export_profile_name(
    scope: HistoryExportScope,
    projection: HistoryExportProjection,
) -> &'static str {
    match (scope, projection) {
        (HistoryExportScope::Summary, HistoryExportProjection::Redacted) => "summary.redacted",
        (HistoryExportScope::Summary, HistoryExportProjection::Display) => "summary.display",
        (HistoryExportScope::CompleteEvidence, HistoryExportProjection::Redacted) => {
            "complete_evidence.redacted"
        }
        (HistoryExportScope::CompleteEvidence, HistoryExportProjection::Display) => {
            "complete_evidence.display"
        }
    }
}

fn hash_length_prefixed(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

#[cfg(unix)]
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CallbackFailure {
    Cancelled,
    Deadline,
    OutputLimit,
    Write,
    Encode,
}

struct ExportControl {
    cancellation: Arc<ExportCancellation>,
    deadline: Instant,
}

impl ExportControl {
    fn check(&self) -> Result<(), CallbackFailure> {
        if self.cancellation.is_cancelled() {
            return Err(CallbackFailure::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(CallbackFailure::Deadline);
        }
        Ok(())
    }
}

pub(crate) fn write_history_export(
    reader: &guiying_store::EvidenceReader,
    context: &ScanHistoryContext,
    request: HistoryExportRequest,
    format: ExportFormat,
    target: &BoundExportTarget,
    cancellation: Arc<ExportCancellation>,
) -> Result<ExportArtifact, ExportTargetError> {
    let limits = ExportLimits::for_scope(request.scope());
    let deadline = Instant::now()
        .checked_add(limits.max_duration)
        .ok_or(ExportTargetError::DeadlineExceeded)?;
    let control = ExportControl {
        cancellation,
        deadline,
    };
    control.check().map_err(map_callback_failure)?;
    let mut temp = target.create_temp()?;
    let mut callback_failure = None;
    let mut encoder_result = None;
    let store_result = reader.with_scan_history_export_snapshot(context, request, |snapshot| {
        if snapshot.expected_record_count() > limits.max_records {
            return Err(StoreError::ReadResultLimit {
                kind: "desktop history export records",
                bytes: i64::from(snapshot.expected_record_count()),
                limit: i64::from(limits.max_records),
            });
        }
        let mut encoder = ExportEncoder::begin(
            temp.file_mut().map_err(|_| StoreError::InvalidInput {
                field: "history_export_target",
                reason: "temporary export target is unavailable".to_owned(),
            })?,
            format,
            request,
            snapshot.expected_record_count(),
            limits.max_output_bytes,
        )
        .map_err(|error| {
            callback_failure = Some(callback_failure_from_target(error));
            StoreError::InvalidInput {
                field: "history_export_encoder",
                reason: "export encoder initialization failed".to_owned(),
            }
        })?;
        loop {
            let batch = snapshot.next_batch(|| {
                control.check().map_err(|failure| {
                    callback_failure = Some(failure);
                    StoreError::InvalidInput {
                        field: "history_export_control",
                        reason: "export interrupted by its control boundary".to_owned(),
                    }
                })?;
                Ok(())
            })?;
            let Some(batch) = batch else {
                break;
            };
            for record in &batch.records {
                if let Err(failure) = control.check() {
                    callback_failure = Some(failure);
                    return Err(StoreError::InvalidInput {
                        field: "history_export_control",
                        reason: "export interrupted by its control boundary".to_owned(),
                    });
                }
                if let Err(error) = encoder.write_record(record) {
                    callback_failure = Some(callback_failure_from_target(error));
                    return Err(StoreError::InvalidInput {
                        field: "history_export_encoder",
                        reason: "export record encoding failed".to_owned(),
                    });
                }
            }
        }
        let result = encoder.finish().map_err(|error| {
            callback_failure = Some(callback_failure_from_target(error));
            StoreError::InvalidInput {
                field: "history_export_encoder",
                reason: "export finalization failed".to_owned(),
            }
        })?;
        encoder_result = Some(result);
        Ok(())
    });
    if store_result.is_err() {
        return Err(callback_failure
            .map(map_callback_failure)
            .unwrap_or(ExportTargetError::StoreFailed));
    }
    control.check().map_err(map_callback_failure)?;
    temp.flush_and_sync()?;
    temp.revalidate(target)?;
    control.check().map_err(map_callback_failure)?;
    let result = encoder_result.ok_or(ExportTargetError::StoreFailed)?;
    let link = control
        .cancellation
        .commit_link(|| target.commit_link(&mut temp))?;
    let publication = target.finish_committed(&mut temp, link);
    Ok(ExportArtifact {
        file_name: target.display_file_name.clone(),
        bytes_written: result.bytes_written,
        record_count: result.record_count,
        logical_digest: result.logical_digest,
        publication_status: publication.status(),
        warning_code: publication.warning_code(),
    })
}

fn callback_failure_from_target(error: ExportTargetError) -> CallbackFailure {
    match error {
        ExportTargetError::Cancelled => CallbackFailure::Cancelled,
        ExportTargetError::DeadlineExceeded => CallbackFailure::Deadline,
        ExportTargetError::OutputLimitExceeded => CallbackFailure::OutputLimit,
        ExportTargetError::EncodeFailed => CallbackFailure::Encode,
        _ => CallbackFailure::Write,
    }
}

fn map_callback_failure(failure: CallbackFailure) -> ExportTargetError {
    match failure {
        CallbackFailure::Cancelled => ExportTargetError::Cancelled,
        CallbackFailure::Deadline => ExportTargetError::DeadlineExceeded,
        CallbackFailure::OutputLimit => ExportTargetError::OutputLimitExceeded,
        CallbackFailure::Write => ExportTargetError::WriteFailed,
        CallbackFailure::Encode => ExportTargetError::EncodeFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guiying_store::{
        HistoryExportDecimal, HistoryExportDuplicateGroupRecord, HistoryExportRecord,
    };

    fn request() -> HistoryExportRequest {
        HistoryExportRequest::new(
            HistoryExportScope::CompleteEvidence,
            HistoryExportProjection::Redacted,
            16,
        )
        .expect("test request")
    }

    fn record() -> HistoryExportRecord {
        HistoryExportRecord::DuplicateGroup(HistoryExportDuplicateGroupRecord {
            scan_run_id: HistoryExportDecimal::from_i64(7),
            group_build_id: HistoryExportDecimal::from_i64(9),
            member_count: HistoryExportDecimal::from_i64(2),
            edge_count: HistoryExportDecimal::from_i64(1),
            independent_file_count: HistoryExportDecimal::from_i64(2),
            logical_reclaimable_bytes: HistoryExportDecimal::from_i64(10),
            finalized_at_ms: HistoryExportDecimal::from_i64(11),
        })
    }

    fn encoded(format: ExportFormat) -> EncoderResult {
        let mut encoder =
            ExportEncoder::begin(Vec::new(), format, request(), 1, 1024 * 1024).expect("encoder");
        encoder.write_record(&record()).expect("record");
        encoder.finish().expect("finish")
    }

    #[derive(Clone)]
    struct CaptureWriter(Arc<StdMutex<Vec<u8>>>);

    impl Write for CaptureWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            let mut bytes = self
                .0
                .lock()
                .map_err(|_| io::Error::other("capture writer poisoned"))?;
            bytes.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn encoded_document(format: ExportFormat, count: u32) -> (EncoderResult, Vec<u8>) {
        let bytes = Arc::new(StdMutex::new(Vec::new()));
        let mut encoder = ExportEncoder::begin(
            CaptureWriter(Arc::clone(&bytes)),
            format,
            request(),
            count,
            1024 * 1024,
        )
        .expect("encoder");
        for _ in 0..count {
            encoder.write_record(&record()).expect("record");
        }
        let result = encoder.finish().expect("finish");
        let document = bytes.lock().expect("capture bytes").clone();
        (result, document)
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[test]
    fn json_and_csv_share_one_logical_digest_and_record_count() {
        let json = encoded(ExportFormat::Json);
        let csv = encoded(ExportFormat::Csv);
        assert_eq!(json.logical_digest, csv.logical_digest);
        assert_eq!(json.record_count, csv.record_count);
        assert_eq!(json.logical_digest.len(), 64);
    }

    #[test]
    fn csv_v1_columns_sequence_and_canonical_records_are_frozen() {
        let (json_result, json_bytes) = encoded_document(ExportFormat::Json, 2);
        let (csv_result, csv_bytes) = encoded_document(ExportFormat::Csv, 2);
        assert_eq!(json_result.logical_digest, csv_result.logical_digest);
        assert!(csv_bytes.starts_with(b"schema_version,profile,section,sequence,record_json\r\n"));

        let canonical = serde_json::to_string(&record()).expect("canonical record");
        for sequence in ["0", "1"] {
            let mut row = Vec::new();
            write_csv_row(
                &mut row,
                &[
                    CSV_SCHEMA_VERSION,
                    export_profile_name(request().scope(), request().projection()),
                    "record",
                    sequence,
                    &canonical,
                ],
            )
            .expect("expected CSV row");
            assert!(contains_bytes(&csv_bytes, &row));
        }

        let json: serde_json::Value =
            serde_json::from_slice(&json_bytes).expect("JSON export document");
        let expected = serde_json::to_value(record()).expect("canonical record value");
        assert_eq!(json["records"][0], expected);
        assert_eq!(json["records"][1], expected);
    }

    #[test]
    fn export_format_parser_accepts_only_the_frozen_v1_names() {
        assert_eq!(ExportFormat::parse("json"), Some(ExportFormat::Json));
        assert_eq!(ExportFormat::parse("csv"), Some(ExportFormat::Csv));
        for rejected in ["JSON", "Csv", "txt", "", "json\0csv"] {
            assert_eq!(ExportFormat::parse(rejected), None);
        }
    }

    #[test]
    fn basename_contract_matches_the_webview_adapter() {
        assert_eq!(
            safe_display_file_name(OsStr::new("封存 报告.json")),
            Some("封存 报告.json")
        );
        for rejected in [
            "",
            ".",
            "..",
            "nested/name.json",
            "nested\\name.json",
            "bad\u{7f}.json",
        ] {
            assert_eq!(safe_display_file_name(OsStr::new(rejected)), None);
        }
        let oversized = format!("{}.json", "a".repeat(1021));
        assert_eq!(safe_display_file_name(OsStr::new(&oversized)), None);
    }

    #[cfg(unix)]
    #[test]
    fn target_extension_must_exactly_match_the_selected_format() {
        let fixture = tempfile::tempdir().expect("fixture");
        for name in ["history.csv", "history.JSON", "history.json.tmp", ".json"] {
            assert_eq!(
                BoundExportTarget::bind(fixture.path().join(name), ExportFormat::Json).err(),
                Some(ExportTargetError::InvalidSelection)
            );
        }
        BoundExportTarget::bind(fixture.path().join("history.json"), ExportFormat::Json)
            .expect("matching extension");
    }

    #[cfg(not(unix))]
    #[test]
    fn target_binding_is_explicitly_fail_closed_without_directory_handle_support() {
        let target = std::env::current_dir()
            .expect("current directory")
            .join("history.json");
        assert_eq!(
            BoundExportTarget::bind(target, ExportFormat::Json).err(),
            Some(ExportTargetError::UnsupportedPlatform)
        );
    }

    #[cfg(unix)]
    #[test]
    fn bound_directory_handle_survives_parent_path_replacement() {
        let fixture = tempfile::tempdir().expect("fixture");
        let selected_parent = fixture.path().join("selected");
        let relocated_parent = fixture.path().join("relocated");
        std::fs::create_dir(&selected_parent).expect("selected directory");
        let target =
            BoundExportTarget::bind(selected_parent.join("history.json"), ExportFormat::Json)
                .expect("bound target");
        std::fs::rename(&selected_parent, &relocated_parent).expect("relocate directory");
        std::fs::create_dir(&selected_parent).expect("replacement directory");

        let mut temp = target.create_temp().expect("relative temporary file");
        temp.file_mut()
            .expect("temporary file")
            .write_all(b"sealed")
            .expect("temporary content");
        temp.flush_and_sync().expect("temporary sync");
        let link = target.commit_link(&mut temp).expect("relative link");
        assert!(matches!(
            target.finish_committed(&mut temp, link),
            PublicationOutcome::Committed | PublicationOutcome::CommittedWithWarning(_)
        ));
        assert_eq!(
            std::fs::read(relocated_parent.join("history.json")).expect("published target"),
            b"sealed"
        );
        assert!(!selected_parent.join("history.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn existing_target_is_rejected_before_any_write() {
        let fixture = tempfile::tempdir().expect("fixture");
        let target = fixture.path().join("history.json");
        std::fs::write(&target, b"preserve").expect("existing target");
        assert_eq!(
            BoundExportTarget::bind(target, ExportFormat::Json).err(),
            Some(ExportTargetError::TargetExists)
        );
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("injected write failure"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("injected flush failure"))
        }
    }

    #[test]
    fn encoder_write_fault_is_terminal_and_never_claims_success() {
        assert_eq!(
            ExportEncoder::begin(FailingWriter, ExportFormat::Json, request(), 1, 1024).err(),
            Some(ExportTargetError::WriteFailed)
        );
    }

    #[test]
    fn counting_writer_enforces_the_exact_output_limit() {
        let mut writer = CountingWriter::new(Vec::new(), 3);
        writer.write_all(b"abc").expect("at limit");
        assert!(writer.write_all(b"d").is_err());
        assert!(writer.limit_exceeded());
    }

    #[test]
    fn cancellation_and_no_replace_commit_share_one_terminal_gate() {
        let cancelled = ExportCancellation::new();
        assert!(cancelled.cancel());
        assert_eq!(
            cancelled.commit_link(|| Ok(LinkCommit {
                identity_verified: true,
            })),
            Err(ExportTargetError::Cancelled)
        );

        let committed = ExportCancellation::new();
        assert!(committed
            .commit_link(|| Ok(LinkCommit {
                identity_verified: true,
            }))
            .is_ok());
        assert!(!committed.cancel());
        assert!(!committed.is_cancelled());
    }

    #[test]
    fn publication_warnings_combine_and_uncertainty_has_explicit_priority() {
        assert_eq!(
            publication_outcome(true, true, true, true),
            PublicationOutcome::CommittedWithWarning("TEMP_CLEANUP_AND_DIRECTORY_SYNC_UNAVAILABLE")
        );
        assert_eq!(
            publication_outcome(false, true, true, true),
            PublicationOutcome::CommitUncertain("TARGET_IDENTITY_UNCERTAIN")
        );
        assert_eq!(
            publication_outcome(true, false, true, true),
            PublicationOutcome::CommitUncertain("TARGET_REVALIDATION_UNCERTAIN")
        );
    }
}
