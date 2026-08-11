use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::compare::compare_bound_files_exact;
use crate::directory_io::{
    BindDirectoryError, BindFileError, BoundDirectory, BoundDirectoryAudit, BoundFile, EntryKind,
};
use crate::error::{ScanError, VerificationError};
use crate::file_io::{snapshot_path, FileSnapshot, StableOpenError};
use crate::model::{
    DuplicateGroup, DuplicateProof, FileId, FileRecord, MediaKind, PathRef, ProgressStage,
    ScanIssue, ScanIssueCode, ScanOptions, ScanProgress, ScanReport, ScanStats, ScanStatus,
    REPORT_SCHEMA_VERSION,
};

const MAX_SAMPLE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_READ_BUFFER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DIRECTORY_DEPTH: u16 = 512;

/// Observer and cancellation interface used by long-running scans and exact
/// verification. Implementations must keep callbacks quick and non-blocking.
pub trait ScanControl: Send + Sync {
    fn is_cancelled(&self) -> bool {
        false
    }

    fn on_progress(&self, _progress: &ScanProgress) {}
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoopScanControl;

impl ScanControl for NoopScanControl {}

#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

impl ScanControl for CancellationToken {
    fn is_cancelled(&self) -> bool {
        self.is_cancelled()
    }
}

#[derive(Clone, Debug)]
pub struct Scanner {
    options: ScanOptions,
    sample_bytes: usize,
    read_buffer_bytes: usize,
}

impl Default for Scanner {
    fn default() -> Self {
        let options = ScanOptions::default();
        Self {
            sample_bytes: options.sample_bytes as usize,
            read_buffer_bytes: options.read_buffer_bytes as usize,
            options,
        }
    }
}

impl Scanner {
    pub fn new(mut options: ScanOptions) -> Result<Self, ScanError> {
        if options.sample_bytes == 0 || options.sample_bytes > MAX_SAMPLE_BYTES {
            return Err(ScanError::InvalidOption(format!(
                "sample_bytes must be in 1..={MAX_SAMPLE_BYTES}"
            )));
        }
        if options.read_buffer_bytes == 0 || options.read_buffer_bytes > MAX_READ_BUFFER_BYTES {
            return Err(ScanError::InvalidOption(format!(
                "read_buffer_bytes must be in 1..={MAX_READ_BUFFER_BYTES}"
            )));
        }
        if options.max_directory_depth == 0 || options.max_directory_depth > MAX_DIRECTORY_DEPTH {
            return Err(ScanError::InvalidOption(format!(
                "max_directory_depth must be in 1..={MAX_DIRECTORY_DEPTH}"
            )));
        }

        options.media_extensions = normalize_values(options.media_extensions, true);
        options.excluded_directory_names =
            normalize_values(options.excluded_directory_names, false);
        options.excluded_directory_prefixes =
            normalize_values(options.excluded_directory_prefixes, false);
        options.excluded_directory_suffixes =
            normalize_values(options.excluded_directory_suffixes, false);

        let sample_bytes = usize::try_from(options.sample_bytes).map_err(|_| {
            ScanError::InvalidOption("sample_bytes does not fit this platform".to_owned())
        })?;
        let read_buffer_bytes = usize::try_from(options.read_buffer_bytes).map_err(|_| {
            ScanError::InvalidOption("read_buffer_bytes does not fit this platform".to_owned())
        })?;

        Ok(Self {
            options,
            sample_bytes,
            read_buffer_bytes,
        })
    }

    pub fn options(&self) -> &ScanOptions {
        &self.options
    }

    pub fn scan<I, P>(&self, roots: I) -> Result<ScanReport, ScanError>
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        self.scan_with_control(roots, &NoopScanControl)
    }

    pub fn scan_with_control<I, P>(
        &self,
        roots: I,
        control: &dyn ScanControl,
    ) -> Result<ScanReport, ScanError>
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        let mut roots: Vec<PathBuf> = roots.into_iter().map(Into::into).collect();
        roots.sort();
        roots.dedup();
        if roots.is_empty() {
            return Err(ScanError::NoRoots);
        }

        let root_sessions = validate_roots(&roots)?;
        let mut scanned = Vec::<ScannedFile>::new();
        let mut issues = Vec::<ScanIssue>::new();
        let mut stats = ScanStats::default();
        let mut seen_paths = BTreeSet::new();
        let mut visited_directory_ids = BTreeSet::<FileId>::new();
        let mut directory_audits = Vec::<BoundDirectoryAudit>::new();
        let mut enumeration_completed = 0_u64;

        for root in &root_sessions {
            if control.is_cancelled() {
                return Ok(finish_report(
                    roots,
                    scanned,
                    Vec::new(),
                    issues,
                    stats,
                    ScanStatus::Cancelled,
                ));
            }

            if root.is_directory {
                if let Some(reason) = self.options.directory_exclusion(&root.path) {
                    return Err(ScanError::ExcludedRoot {
                        path: root.path.clone(),
                        reason,
                    });
                }

                let bound_root = match BoundDirectory::bind_root(root.path.clone(), &root.snapshot)
                {
                    Ok(directory) => directory,
                    Err(error) => {
                        push_directory_binding_issue(&mut issues, root.path.clone(), error, true);
                        return Ok(finish_report(
                            roots,
                            scanned,
                            Vec::new(),
                            issues,
                            stats,
                            ScanStatus::Interrupted,
                        ));
                    }
                };
                if !accept_directory_identity(
                    &bound_root,
                    &mut visited_directory_ids,
                    &mut issues,
                    &mut stats,
                ) {
                    continue;
                }
                let root_device = root.snapshot.device();
                directory_audits.push(bound_root.audit());
                let mut bound_root = bound_root;
                let mut root_names = match bound_root.read_names() {
                    Ok(names) => names,
                    Err(error) => {
                        push_issue(
                            &mut issues,
                            ScanIssueCode::DirectoryUnreadable,
                            bound_root.path().to_path_buf(),
                            error.to_string(),
                        );
                        continue;
                    }
                };
                root_names.sort();
                let mut directories = vec![DirectoryFrame {
                    directory: bound_root,
                    names: root_names,
                    depth: 0,
                }];

                while let Some(mut frame) = directories.pop() {
                    if control.is_cancelled() {
                        return Ok(finish_report(
                            roots,
                            scanned,
                            Vec::new(),
                            issues,
                            stats,
                            ScanStatus::Cancelled,
                        ));
                    }

                    let Some(name) = frame.names.pop() else {
                        continue;
                    };
                    let path = frame.directory.path().join(&name);
                    if !seen_paths.insert(path.clone()) {
                        directories.push(frame);
                        continue;
                    }
                    stats.entries_seen = stats.entries_seen.saturating_add(1);
                    enumeration_completed = enumeration_completed.saturating_add(1);
                    emit_progress(
                        control,
                        ProgressStage::Enumerating,
                        enumeration_completed,
                        None,
                        Some(&path),
                    );
                    if control.is_cancelled() {
                        return Ok(finish_report(
                            roots,
                            scanned,
                            Vec::new(),
                            issues,
                            stats,
                            ScanStatus::Cancelled,
                        ));
                    }

                    let kind = match frame.directory.entry_kind(&name) {
                        Ok(kind) => kind,
                        Err(error) => {
                            push_issue(
                                &mut issues,
                                ScanIssueCode::MetadataUnreadable,
                                path,
                                error.to_string(),
                            );
                            directories.push(frame);
                            continue;
                        }
                    };
                    let mut child_to_visit = None;
                    let child_depth = frame.depth.saturating_add(1);

                    match kind {
                        EntryKind::Symlink => {
                            stats.symlinks_skipped = stats.symlinks_skipped.saturating_add(1);
                            push_issue(
                                &mut issues,
                                ScanIssueCode::SymlinkSkipped,
                                path,
                                "symbolic links are never followed".to_owned(),
                            );
                        }
                        EntryKind::Directory => {
                            if let Some(reason) = self.options.directory_exclusion(&path) {
                                stats.excluded_directories_skipped =
                                    stats.excluded_directories_skipped.saturating_add(1);
                                push_issue(
                                    &mut issues,
                                    ScanIssueCode::DirectoryExcluded,
                                    path,
                                    reason,
                                );
                            } else if child_depth > self.options.max_directory_depth {
                                stats.directory_depth_limit_skipped =
                                    stats.directory_depth_limit_skipped.saturating_add(1);
                                push_issue(
                                    &mut issues,
                                    ScanIssueCode::DirectoryDepthLimitReached,
                                    path,
                                    format!(
                                        "directory depth {child_depth} exceeds the configured safe limit {}",
                                        self.options.max_directory_depth
                                    ),
                                );
                            } else {
                                match frame.directory.bind_child(&name, path.clone()) {
                                    Ok(child) => {
                                        if self.options.stay_on_filesystem
                                            && root_device.is_some()
                                            && child_device(&child) != root_device
                                        {
                                            stats.cross_filesystem_directories_skipped = stats
                                                .cross_filesystem_directories_skipped
                                                .saturating_add(1);
                                            push_issue(
                                                &mut issues,
                                                ScanIssueCode::CrossFilesystemSkipped,
                                                path,
                                                "nested filesystem is outside the scan root volume"
                                                    .to_owned(),
                                            );
                                        } else if accept_directory_identity(
                                            &child,
                                            &mut visited_directory_ids,
                                            &mut issues,
                                            &mut stats,
                                        ) {
                                            child_to_visit = Some(child);
                                        }
                                    }
                                    Err(error) => push_directory_binding_issue(
                                        &mut issues,
                                        path,
                                        error,
                                        false,
                                    ),
                                }
                            }
                        }
                        EntryKind::RegularFile => {
                            if let Some(media_kind) = self.options.media_kind(&path) {
                                match frame.directory.bind_regular_file(&name, path.clone()) {
                                    Ok(bound_file) => {
                                        if self.options.stay_on_filesystem
                                            && root_device.is_some()
                                            && bound_file.snapshot.device() != root_device
                                        {
                                            stats.cross_filesystem_files_skipped = stats
                                                .cross_filesystem_files_skipped
                                                .saturating_add(1);
                                            push_issue(
                                                &mut issues,
                                                ScanIssueCode::CrossFilesystemSkipped,
                                                path,
                                                "file is outside the scan root volume".to_owned(),
                                            );
                                        } else {
                                            add_media_file(
                                                path,
                                                media_kind,
                                                bound_file.snapshot,
                                                bound_file.binding,
                                                &mut scanned,
                                                &mut stats,
                                            );
                                        }
                                    }
                                    Err(error) => push_file_binding_issue(&mut issues, path, error),
                                }
                            } else {
                                stats.non_media_files_skipped =
                                    stats.non_media_files_skipped.saturating_add(1);
                            }
                        }
                        EntryKind::Other => {
                            stats.special_files_skipped =
                                stats.special_files_skipped.saturating_add(1);
                            push_issue(
                                &mut issues,
                                ScanIssueCode::UnsupportedFileType,
                                path,
                                "only regular files are scanned".to_owned(),
                            );
                        }
                    }

                    directories.push(frame);
                    if let Some(mut child) = child_to_visit {
                        directory_audits.push(child.audit());
                        match child.read_names() {
                            Ok(mut names) => {
                                names.sort();
                                directories.push(DirectoryFrame {
                                    directory: child,
                                    names,
                                    depth: child_depth,
                                });
                            }
                            Err(error) => push_issue(
                                &mut issues,
                                ScanIssueCode::DirectoryUnreadable,
                                child.path().to_path_buf(),
                                error.to_string(),
                            ),
                        }
                    }
                }
            } else if seen_paths.insert(root.path.clone()) {
                stats.entries_seen = stats.entries_seen.saturating_add(1);
                if let Some(media_kind) = self.options.media_kind(&root.path) {
                    let binding = match BoundFile::bind_root_file(root.path.clone(), &root.snapshot)
                    {
                        Ok(binding) => binding,
                        Err(error) => {
                            push_issue(
                                &mut issues,
                                ScanIssueCode::RootChangedDuringScan,
                                root.path.clone(),
                                format!("regular-file root could not be bound: {error:?}"),
                            );
                            return Ok(finish_report(
                                roots,
                                scanned,
                                Vec::new(),
                                issues,
                                stats,
                                ScanStatus::Interrupted,
                            ));
                        }
                    };
                    add_media_file(
                        root.path.clone(),
                        media_kind,
                        root.snapshot.clone(),
                        binding,
                        &mut scanned,
                        &mut stats,
                    );
                } else {
                    stats.non_media_files_skipped = stats.non_media_files_skipped.saturating_add(1);
                }
            }
        }

        scanned.sort_by(|left, right| left.path.cmp(&right.path));

        let sample_candidates = candidates_by_size(&scanned);
        let sample_total = sample_candidates.len() as u64;
        for (completed, index) in sample_candidates.into_iter().enumerate() {
            let path = scanned[index].path.clone();
            emit_progress(
                control,
                ProgressStage::Sampling,
                completed as u64,
                Some(sample_total),
                Some(&path),
            );
            if control.is_cancelled() {
                return Ok(finish_report(
                    roots,
                    scanned,
                    Vec::new(),
                    issues,
                    stats,
                    ScanStatus::Cancelled,
                ));
            }

            match sample_fingerprint(
                &scanned[index].binding,
                &scanned[index].snapshot,
                self.sample_bytes,
                control,
            ) {
                Ok((hash, bytes_read)) => {
                    scanned[index].record.sample_fingerprint = Some(hash);
                    stats.files_sampled = stats.files_sampled.saturating_add(1);
                    stats.bytes_sampled = stats.bytes_sampled.saturating_add(bytes_read);
                }
                Err(ReadHashError::Cancelled) => {
                    return Ok(finish_report(
                        roots,
                        scanned,
                        Vec::new(),
                        issues,
                        stats,
                        ScanStatus::Cancelled,
                    ));
                }
                Err(error) => push_hash_issue(&mut issues, path, error),
            }
        }

        let full_candidates = candidates_by_sample(&scanned);
        let full_total = full_candidates.len() as u64;
        for (completed, index) in full_candidates.into_iter().enumerate() {
            let path = scanned[index].path.clone();
            emit_progress(
                control,
                ProgressStage::FullHashing,
                completed as u64,
                Some(full_total),
                Some(&path),
            );
            if control.is_cancelled() {
                return Ok(finish_report(
                    roots,
                    scanned,
                    Vec::new(),
                    issues,
                    stats,
                    ScanStatus::Cancelled,
                ));
            }

            match full_hash(
                &scanned[index].binding,
                &scanned[index].snapshot,
                self.read_buffer_bytes,
                control,
            ) {
                Ok((hash, bytes_read)) => {
                    scanned[index].record.content_hash = Some(hash);
                    stats.files_fully_hashed = stats.files_fully_hashed.saturating_add(1);
                    stats.bytes_fully_hashed = stats.bytes_fully_hashed.saturating_add(bytes_read);
                }
                Err(ReadHashError::Cancelled) => {
                    return Ok(finish_report(
                        roots,
                        scanned,
                        Vec::new(),
                        issues,
                        stats,
                        ScanStatus::Cancelled,
                    ));
                }
                Err(error) => push_hash_issue(&mut issues, path, error),
            }
        }

        let mut groups =
            match build_exact_duplicate_groups(&scanned, control, &mut issues, &mut stats) {
                Ok(groups) => groups,
                Err(ExactBuildError::Cancelled) => {
                    return Ok(finish_report(
                        roots,
                        scanned,
                        Vec::new(),
                        issues,
                        stats,
                        ScanStatus::Cancelled,
                    ));
                }
            };

        let Some(directories_stable) =
            revalidate_directories(&directory_audits, &mut issues, control)
        else {
            return Ok(finish_report(
                roots,
                scanned,
                Vec::new(),
                issues,
                stats,
                ScanStatus::Cancelled,
            ));
        };
        let Some(roots_stable) = revalidate_roots(&root_sessions, &mut issues, control) else {
            return Ok(finish_report(
                roots,
                scanned,
                Vec::new(),
                issues,
                stats,
                ScanStatus::Cancelled,
            ));
        };
        if control.is_cancelled() {
            return Ok(finish_report(
                roots,
                scanned,
                Vec::new(),
                issues,
                stats,
                ScanStatus::Cancelled,
            ));
        }
        let status = if roots_stable && directories_stable {
            emit_progress(
                control,
                ProgressStage::Complete,
                scanned.len() as u64,
                Some(scanned.len() as u64),
                None,
            );
            ScanStatus::Complete
        } else {
            groups.clear();
            ScanStatus::Interrupted
        };
        Ok(finish_report(roots, scanned, groups, issues, stats, status))
    }
}

fn revalidate_directories(
    directories: &[BoundDirectoryAudit],
    issues: &mut Vec<ScanIssue>,
    control: &dyn ScanControl,
) -> Option<bool> {
    let mut stable = true;
    for directory in directories {
        if control.is_cancelled() {
            return None;
        }
        if let Err(error) = directory.revalidate() {
            stable = false;
            push_issue(
                issues,
                ScanIssueCode::DirectoryChangedDuringScan,
                directory.path().to_path_buf(),
                format!("enumerated directory could not be revalidated: {error:?}"),
            );
        }
    }
    (!control.is_cancelled()).then_some(stable)
}

fn normalize_values(values: BTreeSet<String>, trim_dot: bool) -> BTreeSet<String> {
    values
        .into_iter()
        .map(|value| {
            let value = if trim_dot {
                value.trim_start_matches('.')
            } else {
                value.as_str()
            };
            value.to_ascii_lowercase()
        })
        .filter(|value| !value.is_empty())
        .collect()
}

#[derive(Clone, Debug)]
struct RootSession {
    path: PathBuf,
    is_directory: bool,
    snapshot: FileSnapshot,
}

fn validate_roots(roots: &[PathBuf]) -> Result<Vec<RootSession>, ScanError> {
    let mut sessions = Vec::with_capacity(roots.len());
    for root in roots {
        let (metadata, snapshot) =
            snapshot_path(root).map_err(|source| ScanError::RootMetadata {
                path: root.clone(),
                source,
            })?;
        if metadata.file_type().is_symlink() {
            return Err(ScanError::RootIsSymlink(root.clone()));
        }
        if !metadata.file_type().is_file() && !metadata.file_type().is_dir() {
            return Err(ScanError::UnsupportedRoot(root.clone()));
        }
        sessions.push(RootSession {
            path: root.clone(),
            is_directory: metadata.file_type().is_dir(),
            snapshot,
        });
    }
    Ok(sessions)
}

fn revalidate_roots(
    root_sessions: &[RootSession],
    issues: &mut Vec<ScanIssue>,
    control: &dyn ScanControl,
) -> Option<bool> {
    let mut stable = true;
    for root in root_sessions {
        if control.is_cancelled() {
            return None;
        }
        let result = snapshot_path(&root.path);
        match result {
            Ok((metadata, snapshot))
                if metadata.file_type().is_dir() == root.is_directory
                    && snapshot == root.snapshot => {}
            Ok(_) => {
                stable = false;
                push_issue(
                    issues,
                    ScanIssueCode::RootChangedDuringScan,
                    root.path.clone(),
                    "scan root identity, device, or change time changed".to_owned(),
                );
            }
            Err(error) => {
                stable = false;
                push_issue(
                    issues,
                    ScanIssueCode::RootChangedDuringScan,
                    root.path.clone(),
                    format!("scan root could not be revalidated: {error}"),
                );
            }
        }
    }
    (!control.is_cancelled()).then_some(stable)
}

fn child_device(directory: &BoundDirectory) -> Option<u64> {
    directory.device()
}

fn accept_directory_identity(
    directory: &BoundDirectory,
    visited: &mut BTreeSet<FileId>,
    issues: &mut Vec<ScanIssue>,
    stats: &mut ScanStats,
) -> bool {
    let Some(identity) = directory.identity() else {
        push_issue(
            issues,
            ScanIssueCode::MetadataUnreadable,
            directory.path().to_path_buf(),
            "opened directory has no stable device/inode identity".to_owned(),
        );
        return false;
    };
    if visited.insert(identity) {
        true
    } else {
        stats.directory_identity_revisits_skipped =
            stats.directory_identity_revisits_skipped.saturating_add(1);
        push_issue(
            issues,
            ScanIssueCode::DirectoryIdentityAlreadyVisited,
            directory.path().to_path_buf(),
            format!(
                "directory identity ({}, {}) was already visited; possible alias or mount loop",
                identity.device, identity.inode
            ),
        );
        false
    }
}

fn add_media_file(
    path: PathBuf,
    media_kind: MediaKind,
    snapshot: FileSnapshot,
    binding: BoundFile,
    scanned: &mut Vec<ScannedFile>,
    stats: &mut ScanStats,
) {
    stats.media_files = stats.media_files.saturating_add(1);
    scanned.push(ScannedFile {
        record: FileRecord {
            path: PathRef::from_path(&path),
            media_kind,
            size: snapshot.len,
            modified: snapshot.modified_timestamp(),
            created: snapshot.created_timestamp(),
            file_id: snapshot.file_id,
            hard_link_count: snapshot.hard_link_count,
            sample_fingerprint: None,
            content_hash: None,
        },
        path,
        snapshot,
        binding,
    });
}

#[derive(Clone, Debug)]
struct ScannedFile {
    record: FileRecord,
    path: PathBuf,
    snapshot: FileSnapshot,
    binding: BoundFile,
}

struct DirectoryFrame {
    directory: BoundDirectory,
    names: Vec<OsString>,
    depth: u16,
}

fn candidates_by_size(scanned: &[ScannedFile]) -> Vec<usize> {
    let mut groups = BTreeMap::<u64, Vec<usize>>::new();
    for (index, file) in scanned.iter().enumerate() {
        groups.entry(file.record.size).or_default().push(index);
    }
    groups
        .into_values()
        .filter(|indices| indices.len() > 1)
        .flatten()
        .collect()
}

fn candidates_by_sample(scanned: &[ScannedFile]) -> Vec<usize> {
    let mut groups = BTreeMap::<(u64, String), Vec<usize>>::new();
    for (index, file) in scanned.iter().enumerate() {
        if let Some(sample) = &file.record.sample_fingerprint {
            groups
                .entry((file.record.size, sample.clone()))
                .or_default()
                .push(index);
        }
    }
    groups
        .into_values()
        .filter(|indices| indices.len() > 1)
        .flatten()
        .collect()
}

#[derive(Debug)]
enum ReadHashError {
    Cancelled,
    Io(std::io::Error),
    NotRegular,
    Changed,
}

fn sample_fingerprint(
    binding: &BoundFile,
    expected: &FileSnapshot,
    sample_bytes: usize,
    control: &dyn ScanControl,
) -> Result<(String, u64), ReadHashError> {
    let (mut file, before) = binding.open_stable(expected).map_err(map_stable_open)?;
    let (chunk, offsets) = sample_layout(before.len, sample_bytes);

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying-sample-v1\0");
    hasher.update(&before.len.to_le_bytes());
    hasher.update(&(sample_bytes as u64).to_le_bytes());
    let mut buffer = vec![0_u8; chunk];
    let mut bytes_read = 0_u64;

    for offset in offsets {
        if control.is_cancelled() {
            return Err(ReadHashError::Cancelled);
        }
        hasher.update(&offset.to_le_bytes());
        hasher.update(&(chunk as u64).to_le_bytes());
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| classify_read_error(binding, &file, &before, error))?;
        file.read_exact(&mut buffer)
            .map_err(|error| classify_read_error(binding, &file, &before, error))?;
        hasher.update(&buffer);
        bytes_read = bytes_read.saturating_add(chunk as u64);
    }

    verify_unchanged(binding, &file, &before)?;
    Ok((hasher.finalize().to_hex().to_string(), bytes_read))
}

/// Select at most three non-overlapping sample windows. Keeping the windows
/// disjoint guarantees that the reported physical bytes read never exceeds
/// the immutable file length, even when a file is only slightly larger than
/// the configured per-window target.
pub(crate) fn sample_layout(length: u64, sample_bytes: usize) -> (usize, Vec<u64>) {
    let target = sample_bytes as u64;
    if length <= target {
        return (length as usize, vec![0]);
    }
    let chunk = target.min((length / 3).max(1));
    let mut offsets = vec![0, (length - chunk) / 2, length - chunk];
    offsets.sort_unstable();
    offsets.dedup();
    (chunk as usize, offsets)
}

fn full_hash(
    binding: &BoundFile,
    expected: &FileSnapshot,
    buffer_bytes: usize,
    control: &dyn ScanControl,
) -> Result<(String, u64), ReadHashError> {
    let (mut file, before) = binding.open_stable(expected).map_err(map_stable_open)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| classify_read_error(binding, &file, &before, error))?;
    let (digest, bytes_read) = hash_reader_exact(&mut file, before.len, buffer_bytes, control)
        .map_err(|error| match error {
            ReadHashError::Io(error) => classify_read_error(binding, &file, &before, error),
            other => other,
        })?;

    verify_unchanged(binding, &file, &before)?;
    Ok((digest, bytes_read))
}

fn hash_reader_exact(
    reader: &mut impl Read,
    expected_len: u64,
    buffer_bytes: usize,
    control: &dyn ScanControl,
) -> Result<(String, u64), ReadHashError> {
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; buffer_bytes];
    let mut bytes_read = 0_u64;

    loop {
        if control.is_cancelled() {
            return Err(ReadHashError::Cancelled);
        }
        let read = match reader.read(&mut buffer) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(ReadHashError::Io(error)),
        };
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        bytes_read = bytes_read.saturating_add(read as u64);
    }

    if bytes_read != expected_len {
        let kind = if bytes_read < expected_len {
            io::ErrorKind::UnexpectedEof
        } else {
            io::ErrorKind::InvalidData
        };
        return Err(ReadHashError::Io(io::Error::new(
            kind,
            format!("expected {expected_len} bytes, read {bytes_read}"),
        )));
    }

    Ok((hasher.finalize().to_hex().to_string(), bytes_read))
}

fn classify_read_error(
    binding: &BoundFile,
    file: &File,
    before: &FileSnapshot,
    error: std::io::Error,
) -> ReadHashError {
    match binding.unchanged_after_read(file, before) {
        Ok(false) => ReadHashError::Changed,
        Ok(true) | Err(_) => ReadHashError::Io(error),
    }
}

fn verify_unchanged(
    binding: &BoundFile,
    file: &File,
    before: &FileSnapshot,
) -> Result<(), ReadHashError> {
    match binding.unchanged_after_read(file, before) {
        Ok(true) => Ok(()),
        Ok(false) => Err(ReadHashError::Changed),
        Err(error) => Err(ReadHashError::Io(error)),
    }
}

fn map_stable_open(error: StableOpenError) -> ReadHashError {
    match error {
        StableOpenError::Io(error) => ReadHashError::Io(error),
        StableOpenError::NotRegular => ReadHashError::NotRegular,
        StableOpenError::Changed => ReadHashError::Changed,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PairRelation {
    Equal,
    Different,
    ExcludeLeft,
    ExcludeRight,
    ExcludeBoth,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExactBuildError {
    Cancelled,
}

fn partition_equivalence_classes<F>(
    indices: Vec<usize>,
    mut relation: F,
) -> Result<Vec<Vec<usize>>, ExactBuildError>
where
    F: FnMut(usize, usize) -> PairRelation,
{
    let mut classes = Vec::<Vec<usize>>::new();
    let mut excluded = BTreeSet::<usize>::new();

    for candidate in indices {
        if excluded.contains(&candidate) {
            continue;
        }
        let mut placed = false;
        let mut class_index = 0;
        while class_index < classes.len() && !excluded.contains(&candidate) {
            classes[class_index].retain(|index| !excluded.contains(index));
            if classes[class_index].is_empty() {
                classes.remove(class_index);
                continue;
            }

            let representative = classes[class_index][0];
            match relation(representative, candidate) {
                PairRelation::Equal => {
                    classes[class_index].push(candidate);
                    placed = true;
                    break;
                }
                PairRelation::Different => class_index += 1,
                PairRelation::ExcludeLeft => {
                    excluded.insert(representative);
                }
                PairRelation::ExcludeRight => {
                    excluded.insert(candidate);
                }
                PairRelation::ExcludeBoth => {
                    excluded.insert(representative);
                    excluded.insert(candidate);
                }
                PairRelation::Cancelled => return Err(ExactBuildError::Cancelled),
            }
        }
        if !placed && !excluded.contains(&candidate) {
            classes.push(vec![candidate]);
        }
    }

    for class in &mut classes {
        class.retain(|index| !excluded.contains(index));
    }
    classes.retain(|class| !class.is_empty());
    Ok(classes)
}

fn build_exact_duplicate_groups(
    scanned: &[ScannedFile],
    control: &dyn ScanControl,
    issues: &mut Vec<ScanIssue>,
    stats: &mut ScanStats,
) -> Result<Vec<DuplicateGroup>, ExactBuildError> {
    let mut hash_buckets = BTreeMap::<(u64, String), Vec<usize>>::new();
    for (index, file) in scanned.iter().enumerate() {
        if let Some(hash) = &file.record.content_hash {
            hash_buckets
                .entry((file.record.size, hash.clone()))
                .or_default()
                .push(index);
        }
    }

    let mut groups = Vec::new();
    for ((size, content_hash), indices) in hash_buckets {
        if indices.len() < 2 {
            continue;
        }
        let classes = partition_equivalence_classes(indices, |left, right| {
            let left_file = &scanned[left];
            let right_file = &scanned[right];
            emit_progress(
                control,
                ProgressStage::ExactComparing,
                stats.exact_comparisons,
                None,
                Some(&right_file.path),
            );
            if control.is_cancelled() {
                return PairRelation::Cancelled;
            }

            match compare_bound_files_exact(
                &left_file.binding,
                &left_file.snapshot,
                &right_file.binding,
                &right_file.snapshot,
                control,
            ) {
                Ok(comparison) => {
                    stats.exact_comparisons = stats.exact_comparisons.saturating_add(1);
                    stats.bytes_exactly_compared = stats
                        .bytes_exactly_compared
                        .saturating_add(comparison.bytes_compared);
                    if comparison.identical {
                        PairRelation::Equal
                    } else {
                        push_issue(
                            issues,
                            ScanIssueCode::HashCollisionDetected,
                            right_file.path.clone(),
                            format!(
                                "full BLAKE3 matched but bytes differed from `{}`",
                                left_file.record.path.display
                            ),
                        );
                        PairRelation::Different
                    }
                }
                Err(VerificationError::Cancelled) => PairRelation::Cancelled,
                Err(error) => {
                    let failed_path = error.path().map(Path::to_path_buf);
                    let relation = match failed_path.as_deref() {
                        Some(path) if path == left_file.path => PairRelation::ExcludeLeft,
                        Some(path) if path == right_file.path => PairRelation::ExcludeRight,
                        _ => PairRelation::ExcludeBoth,
                    };
                    let issue_path = failed_path.unwrap_or_else(|| right_file.path.clone());
                    let code = if matches!(error, VerificationError::ChangedDuringRead(_)) {
                        ScanIssueCode::ChangedDuringScan
                    } else {
                        ScanIssueCode::ExactVerificationFailed
                    };
                    push_issue(issues, code, issue_path, error.to_string());
                    relation
                }
            }
        })?;

        for mut class in classes {
            class.retain(|index| {
                match scanned[*index]
                    .binding
                    .open_stable(&scanned[*index].snapshot)
                {
                    Ok(_) => true,
                    Err(StableOpenError::Changed | StableOpenError::NotRegular) => {
                        push_issue(
                            issues,
                            ScanIssueCode::ChangedDuringScan,
                            scanned[*index].path.clone(),
                            "file changed after byte-for-byte verification".to_owned(),
                        );
                        false
                    }
                    Err(StableOpenError::Io(error)) => {
                        push_issue(
                            issues,
                            ScanIssueCode::ExactVerificationFailed,
                            scanned[*index].path.clone(),
                            format!("file could not be revalidated: {error}"),
                        );
                        false
                    }
                }
            });
            if class.len() < 2 {
                continue;
            }

            let mut files: Vec<FileRecord> = class
                .into_iter()
                .map(|index| scanned[index].record.clone())
                .collect();
            files.sort_by(|left, right| left.path.cmp(&right.path));
            groups.push(make_duplicate_group(size, content_hash.clone(), files));
        }
    }
    groups.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(groups)
}

fn make_duplicate_group(size: u64, content_hash: String, files: Vec<FileRecord>) -> DuplicateGroup {
    let class_discriminator = duplicate_class_discriminator(&files);
    let mut known_ids = BTreeSet::new();
    let mut unknown_id_count = 0_u64;
    for file in &files {
        if let Some(id) = file.file_id {
            known_ids.insert(id);
        } else {
            unknown_id_count = unknown_id_count.saturating_add(1);
        }
    }
    let independent_file_count = (known_ids.len() as u64).saturating_add(unknown_id_count);
    let logical_reclaimable_bytes = size.saturating_mul(independent_file_count.saturating_sub(1));
    DuplicateGroup {
        id: format!("blake3:{content_hash}:{size}:class:{class_discriminator}"),
        content_hash,
        size,
        files,
        proof: DuplicateProof::ByteForByte,
        independent_file_count,
        logical_reclaimable_bytes,
    }
}

fn duplicate_class_discriminator(files: &[FileRecord]) -> String {
    let mut paths: Vec<_> = files.iter().map(|file| &file.path).collect();
    paths.sort();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying-duplicate-class-v1\0");
    for path in paths {
        let encoding = match path.encoding {
            crate::model::PathEncoding::UnixBytes => b"unix\0".as_slice(),
            crate::model::PathEncoding::WindowsUtf16Le => b"windows-utf16le\0".as_slice(),
            crate::model::PathEncoding::Utf8 => b"utf8\0".as_slice(),
        };
        hasher.update(encoding);
        hasher.update(&(path.raw_base64.len() as u64).to_le_bytes());
        hasher.update(path.raw_base64.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn emit_progress(
    control: &dyn ScanControl,
    stage: ProgressStage,
    completed: u64,
    total: Option<u64>,
    path: Option<&Path>,
) {
    control.on_progress(&ScanProgress {
        stage,
        completed,
        total,
        current_path: path.map(PathRef::from_path),
    });
}

fn push_hash_issue(issues: &mut Vec<ScanIssue>, path: PathBuf, error: ReadHashError) {
    match error {
        ReadHashError::Io(error) => push_issue(
            issues,
            ScanIssueCode::FileUnreadable,
            path,
            error.to_string(),
        ),
        ReadHashError::NotRegular => push_issue(
            issues,
            ScanIssueCode::UnsupportedFileType,
            path,
            "entry stopped being a regular file".to_owned(),
        ),
        ReadHashError::Changed => push_issue(
            issues,
            ScanIssueCode::ChangedDuringScan,
            path,
            "file metadata or identity changed after enumeration".to_owned(),
        ),
        ReadHashError::Cancelled => {}
    }
}

fn push_directory_binding_issue(
    issues: &mut Vec<ScanIssue>,
    path: PathBuf,
    error: BindDirectoryError,
    root: bool,
) {
    let (code, detail) = match error {
        BindDirectoryError::Io(error) => (
            if root {
                ScanIssueCode::RootChangedDuringScan
            } else {
                ScanIssueCode::DirectoryUnreadable
            },
            error.to_string(),
        ),
        BindDirectoryError::NotDirectory => (
            ScanIssueCode::ChangedDuringScan,
            "entry stopped being a directory".to_owned(),
        ),
        BindDirectoryError::Changed => (
            if root {
                ScanIssueCode::RootChangedDuringScan
            } else {
                ScanIssueCode::ChangedDuringScan
            },
            "directory identity changed before its handle was bound".to_owned(),
        ),
    };
    push_issue(issues, code, path, detail);
}

fn push_file_binding_issue(issues: &mut Vec<ScanIssue>, path: PathBuf, error: BindFileError) {
    match error {
        BindFileError::Io(error) => push_issue(
            issues,
            ScanIssueCode::FileUnreadable,
            path,
            error.to_string(),
        ),
        BindFileError::NotRegular => push_issue(
            issues,
            ScanIssueCode::ChangedDuringScan,
            path,
            "entry stopped being a regular file before it was bound".to_owned(),
        ),
    }
}

fn push_issue(issues: &mut Vec<ScanIssue>, code: ScanIssueCode, path: PathBuf, detail: String) {
    issues.push(ScanIssue {
        code,
        path: PathRef::from_path(&path),
        detail,
    });
}

fn issue_makes_report_partial(code: ScanIssueCode) -> bool {
    matches!(
        code,
        ScanIssueCode::DirectoryIdentityAlreadyVisited
            | ScanIssueCode::MetadataUnreadable
            | ScanIssueCode::DirectoryUnreadable
            | ScanIssueCode::DirectoryChangedDuringScan
            | ScanIssueCode::DirectoryDepthLimitReached
            | ScanIssueCode::FileUnreadable
            | ScanIssueCode::ChangedDuringScan
            | ScanIssueCode::ExactVerificationFailed
            | ScanIssueCode::HashCollisionDetected
    )
}

fn finish_report(
    roots: Vec<PathBuf>,
    scanned: Vec<ScannedFile>,
    duplicate_groups: Vec<DuplicateGroup>,
    mut issues: Vec<ScanIssue>,
    mut stats: ScanStats,
    requested_status: ScanStatus,
) -> ScanReport {
    issues.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.code.cmp(&right.code))
            .then_with(|| left.detail.cmp(&right.detail))
    });
    let status = if requested_status == ScanStatus::Complete
        && issues
            .iter()
            .any(|issue| issue_makes_report_partial(issue.code))
    {
        ScanStatus::Partial
    } else {
        requested_status
    };
    let duplicate_groups = if matches!(status, ScanStatus::Cancelled | ScanStatus::Interrupted) {
        Vec::new()
    } else {
        duplicate_groups
    };
    stats.issues = issues.len() as u64;
    stats.duplicate_groups = duplicate_groups.len() as u64;
    stats.duplicate_files = duplicate_groups
        .iter()
        .map(|group| group.files.len() as u64)
        .sum();
    stats.logical_reclaimable_bytes = duplicate_groups
        .iter()
        .map(|group| group.logical_reclaimable_bytes)
        .fold(0_u64, u64::saturating_add);

    ScanReport {
        schema_version: REPORT_SCHEMA_VERSION,
        roots: roots.iter().map(PathRef::from).collect(),
        files: scanned.into_iter().map(|file| file.record).collect(),
        duplicate_groups,
        issues,
        stats,
        status,
        cancelled: status == ScanStatus::Cancelled,
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, ErrorKind};
    use std::path::Path;

    use crate::model::{FileRecord, MediaKind, PathRef};

    use super::{
        hash_reader_exact, make_duplicate_group, partition_equivalence_classes,
        revalidate_directories, revalidate_roots, sample_layout, CancellationToken,
        NoopScanControl, PairRelation, ReadHashError,
    };

    #[test]
    fn sample_windows_never_overlap_or_exceed_the_file() {
        for length in 0_u64..=300_000 {
            let (chunk, offsets) = sample_layout(length, 64 * 1024);
            let chunk = chunk as u64;
            assert!(offsets.len() <= 3);
            assert!(offsets.iter().all(|offset| offset + chunk <= length));
            assert!(offsets.windows(2).all(|pair| pair[0] + chunk <= pair[1]));
            assert!(chunk.saturating_mul(offsets.len() as u64) <= length);
        }
    }

    #[test]
    fn final_revalidation_observes_cancellation_before_completion() {
        let token = CancellationToken::new();
        token.cancel();
        let mut issues = Vec::new();

        assert_eq!(revalidate_directories(&[], &mut issues, &token), None);
        assert_eq!(revalidate_roots(&[], &mut issues, &token), None);
        assert!(issues.is_empty());
    }

    #[test]
    fn full_hash_rejects_premature_eof() {
        let mut reader = Cursor::new(b"abc");

        let error = hash_reader_exact(&mut reader, 4, 2, &NoopScanControl)
            .expect_err("a short hash input must fail closed");

        assert!(matches!(
            error,
            ReadHashError::Io(error) if error.kind() == ErrorKind::UnexpectedEof
        ));
    }

    #[test]
    fn full_hash_rejects_data_beyond_the_declared_length() {
        let mut reader = Cursor::new(b"abcd");

        let error = hash_reader_exact(&mut reader, 3, 2, &NoopScanControl)
            .expect_err("an overlong hash input must fail closed");

        assert!(matches!(
            error,
            ReadHashError::Io(error) if error.kind() == ErrorKind::InvalidData
        ));
    }

    #[test]
    fn a_single_hash_bucket_is_partitioned_by_byte_equality() {
        let classes = partition_equivalence_classes(vec![0, 1, 2, 3], |left, right| {
            if left % 2 == right % 2 {
                PairRelation::Equal
            } else {
                PairRelation::Different
            }
        })
        .expect("partition succeeds");

        assert_eq!(classes, vec![vec![0, 2], vec![1, 3]]);
    }

    #[test]
    fn comparison_failure_excludes_the_affected_member() {
        let classes = partition_equivalence_classes(vec![0, 1, 2], |_left, right| {
            if right == 1 {
                PairRelation::ExcludeRight
            } else {
                PairRelation::Equal
            }
        });

        assert_eq!(classes, Ok(vec![vec![0, 2]]));
    }

    #[test]
    fn byte_classes_from_one_hash_bucket_have_unique_stable_ids() {
        let first = vec![record("/photos/a.jpg"), record("/photos/b.jpg")];
        let mut first_reversed = first.clone();
        first_reversed.reverse();
        let second = vec![record("/photos/c.jpg"), record("/photos/d.jpg")];

        let first_group = make_duplicate_group(9, "same-hash".to_owned(), first);
        let reversed_group = make_duplicate_group(9, "same-hash".to_owned(), first_reversed);
        let second_group = make_duplicate_group(9, "same-hash".to_owned(), second);

        assert_eq!(first_group.id, reversed_group.id);
        assert_ne!(first_group.id, second_group.id);
    }

    fn record(path: &str) -> FileRecord {
        FileRecord {
            path: PathRef::from_path(Path::new(path)),
            media_kind: MediaKind::Image,
            size: 9,
            modified: None,
            created: None,
            file_id: None,
            hard_link_count: None,
            sample_fingerprint: Some("sample".to_owned()),
            content_hash: Some("same-hash".to_owned()),
        }
    }
}
