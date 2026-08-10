use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use filetime::FileTime;
use guiying_core::{
    compare_files_exact, files_are_identical, DuplicateProof, PathRef, ProgressStage, ScanControl,
    ScanIssue, ScanIssueCode, ScanOptions, ScanProgress, ScanStatus, Scanner, VerificationError,
    REPORT_SCHEMA_VERSION,
};
use tempfile::TempDir;

fn write_media(directory: &Path, name: &str, contents: &[u8]) -> PathBuf {
    let path = directory.join(name);
    fs::write(&path, contents).expect("write fixture");
    path
}

fn progress_path_is(progress: &ScanProgress, expected: &Path) -> bool {
    progress
        .current_path
        .as_ref()
        .and_then(|path| path.to_path_buf().ok())
        .as_deref()
        == Some(expected)
}

#[test]
fn same_contents_with_different_names_and_times_are_grouped() {
    let temporary = TempDir::new().expect("tempdir");
    let contents = vec![0x5a; 200_000];
    let first = write_media(temporary.path(), "IMG_0001.HEIC", &contents);
    let second = write_media(temporary.path(), "copied-on-vacation.heic", &contents);
    filetime::set_file_mtime(&first, FileTime::from_unix_time(1_600_000_000, 123))
        .expect("set first mtime");
    filetime::set_file_mtime(&second, FileTime::from_unix_time(1_700_000_000, 456))
        .expect("set second mtime");

    let report = Scanner::default()
        .scan([temporary.path()])
        .expect("scan succeeds");

    assert_eq!(report.schema_version, REPORT_SCHEMA_VERSION);
    assert_eq!(report.files.len(), 2);
    assert_ne!(report.files[0].modified, report.files[1].modified);
    assert_eq!(report.duplicate_groups.len(), 1);
    assert_eq!(report.duplicate_groups[0].files.len(), 2);
    assert_eq!(
        report.duplicate_groups[0].proof,
        DuplicateProof::ByteForByte
    );
    assert_eq!(report.stats.exact_comparisons, 1);
    assert_eq!(
        report.duplicate_groups[0].content_hash,
        blake3::hash(&contents).to_hex().as_str()
    );
    assert_eq!(
        report.stats.logical_reclaimable_bytes,
        contents.len() as u64
    );
    assert!(report.issues.is_empty());
}

#[test]
fn same_size_with_different_samples_is_rejected_early() {
    let temporary = TempDir::new().expect("tempdir");
    write_media(temporary.path(), "one.jpg", b"AAAA1111");
    write_media(temporary.path(), "two.jpg", b"BBBB2222");

    let report = Scanner::default()
        .scan([temporary.path()])
        .expect("scan succeeds");

    assert!(report.duplicate_groups.is_empty());
    assert_eq!(report.stats.files_sampled, 2);
    assert_eq!(report.stats.files_fully_hashed, 0);
}

#[test]
fn a_sample_collision_is_resolved_by_the_full_hash() {
    let temporary = TempDir::new().expect("tempdir");
    // With four-byte first/middle/last samples these differ only in an
    // unsampled range, forcing the full-hash stage to decide.
    write_media(temporary.path(), "one.jpg", b"AAAAxxxxMMMMzzzzTTTT");
    write_media(temporary.path(), "two.jpg", b"AAAAyyyyMMMMyyyyTTTT");
    let options = ScanOptions {
        sample_bytes: 4,
        read_buffer_bytes: 8,
        ..ScanOptions::default()
    };

    let report = Scanner::new(options)
        .expect("valid options")
        .scan([temporary.path()])
        .expect("scan succeeds");

    assert!(report.duplicate_groups.is_empty());
    assert_eq!(report.stats.files_fully_hashed, 2);
    assert_ne!(report.files[0].content_hash, report.files[1].content_hash);
}

#[cfg(unix)]
#[test]
fn symbolic_links_are_reported_and_never_followed() {
    use std::os::unix::fs::symlink;

    let temporary = TempDir::new().expect("tempdir");
    let root = temporary.path().join("scan-root");
    fs::create_dir(&root).expect("create scan root");
    let outside = write_media(temporary.path(), "outside.jpg", b"private media bytes");
    symlink(&outside, root.join("looks-like-a-photo.jpg")).expect("create symlink");

    let report = Scanner::default().scan([&root]).expect("scan succeeds");

    assert!(report.files.is_empty());
    assert_eq!(report.stats.symlinks_skipped, 1);
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.code == ScanIssueCode::SymlinkSkipped));
    assert!(matches!(
        files_are_identical(root.join("looks-like-a-photo.jpg"), &outside),
        Err(VerificationError::Open { .. }) | Err(VerificationError::NotRegularFile(_))
    ));
}

#[cfg(unix)]
#[test]
fn the_same_opened_directory_identity_is_visited_only_once() {
    let temporary = TempDir::new().expect("tempdir");
    let root = temporary.path().join("scan-root");
    let lexical_anchor = root.join("lexical-anchor");
    fs::create_dir(&root).expect("create scan root");
    fs::create_dir(&lexical_anchor).expect("create lexical anchor");
    write_media(&root, "photo.jpg", b"one media file");

    // These roots are lexically distinct, but `lexical-anchor/..` resolves to
    // the same opened directory identity as `root` without using a symlink.
    let alias = lexical_anchor.join("..");
    let report = Scanner::default()
        .scan([root.as_path(), alias.as_path()])
        .expect("scan succeeds");

    // Directory IDs can be unreliable on unknown FUSE/network drivers. The
    // scanner de-duplicates the identity to prevent loops, but keeps the
    // report partial until a future capability profile can establish trust.
    assert_eq!(report.status, ScanStatus::Partial);
    assert_eq!(report.files.len(), 1);
    assert_eq!(report.stats.directory_identity_revisits_skipped, 1);
    assert_eq!(
        report
            .issues
            .iter()
            .filter(|issue| issue.code == ScanIssueCode::DirectoryIdentityAlreadyVisited)
            .count(),
        1
    );
}

struct ReplaceAtSampling {
    target: PathBuf,
    replacement: PathBuf,
    done: AtomicBool,
}

impl ScanControl for ReplaceAtSampling {
    fn on_progress(&self, progress: &ScanProgress) {
        if progress.stage == ProgressStage::Sampling
            && progress_path_is(progress, &self.target)
            && !self.done.swap(true, Ordering::AcqRel)
        {
            fs::rename(&self.replacement, &self.target).expect("replace fixture during scan");
        }
    }
}

#[cfg(unix)]
#[test]
fn a_file_replaced_after_enumeration_is_excluded() {
    let temporary = TempDir::new().expect("tempdir");
    let first = write_media(temporary.path(), "a.jpg", b"same-size-content");
    write_media(temporary.path(), "b.jpg", b"same-size-content");
    let replacement = write_media(temporary.path(), "replacement.bin", b"changed-content!!");
    assert_eq!(
        fs::metadata(&first).unwrap().len(),
        fs::metadata(&replacement).unwrap().len()
    );
    let control = ReplaceAtSampling {
        target: first,
        replacement,
        done: AtomicBool::new(false),
    };

    let report = Scanner::default()
        .scan_with_control([temporary.path()], &control)
        .expect("scan completes with a recoverable issue");

    assert!(report.duplicate_groups.is_empty());
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.code == ScanIssueCode::ChangedDuringScan));
}

struct RemoveAtSampling {
    target: PathBuf,
    done: AtomicBool,
}

impl ScanControl for RemoveAtSampling {
    fn on_progress(&self, progress: &ScanProgress) {
        if progress.stage == ProgressStage::Sampling
            && progress_path_is(progress, &self.target)
            && !self.done.swap(true, Ordering::AcqRel)
        {
            fs::remove_file(&self.target).expect("remove fixture during scan");
        }
    }
}

#[test]
fn a_file_that_becomes_unreadable_is_an_issue_not_a_scan_failure() {
    let temporary = TempDir::new().expect("tempdir");
    let first = write_media(temporary.path(), "a.jpg", b"same content");
    write_media(temporary.path(), "b.jpg", b"same content");
    let control = RemoveAtSampling {
        target: first,
        done: AtomicBool::new(false),
    };

    let report = Scanner::default()
        .scan_with_control([temporary.path()], &control)
        .expect("scan completes with a recoverable issue");

    assert!(report.duplicate_groups.is_empty());
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.code == ScanIssueCode::FileUnreadable));
}

#[test]
fn scan_report_round_trips_through_json() {
    let temporary = TempDir::new().expect("tempdir");
    write_media(temporary.path(), "a.png", b"duplicate");
    write_media(temporary.path(), "b.png", b"duplicate");
    let report = Scanner::default()
        .scan([temporary.path()])
        .expect("scan succeeds");

    let json = serde_json::to_string_pretty(&report).expect("serialize report");
    let decoded = serde_json::from_str(&json).expect("deserialize report");
    assert_eq!(report, decoded);
}

struct CancelAtSampling {
    cancelled: AtomicBool,
}

impl ScanControl for CancelAtSampling {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    fn on_progress(&self, progress: &ScanProgress) {
        if progress.stage == ProgressStage::Sampling {
            self.cancelled.store(true, Ordering::Release);
        }
    }
}

#[test]
fn cancellation_returns_a_safe_partial_report() {
    let temporary = TempDir::new().expect("tempdir");
    write_media(temporary.path(), "a.jpg", b"duplicate");
    write_media(temporary.path(), "b.jpg", b"duplicate");
    let control = CancelAtSampling {
        cancelled: AtomicBool::new(false),
    };

    let report = Scanner::default()
        .scan_with_control([temporary.path()], &control)
        .expect("cancellation is not a scan failure");

    assert!(report.cancelled);
    assert_eq!(report.status, ScanStatus::Cancelled);
    assert_eq!(report.files.len(), 2);
    assert!(report.duplicate_groups.is_empty());
    assert_eq!(report.stats.files_sampled, 0);
}

#[cfg(unix)]
#[test]
fn hard_link_aliases_do_not_claim_reclaimable_storage() {
    let temporary = TempDir::new().expect("tempdir");
    let first = write_media(temporary.path(), "a.jpg", b"one physical file");
    fs::hard_link(&first, temporary.path().join("b.jpg")).expect("create hard link");

    let report = Scanner::default()
        .scan([temporary.path()])
        .expect("scan succeeds");

    assert_eq!(report.duplicate_groups.len(), 1);
    assert_eq!(report.duplicate_groups[0].independent_file_count, 1);
    assert_eq!(report.duplicate_groups[0].logical_reclaimable_bytes, 0);
}

struct ChangeAtExactComparison {
    target: PathBuf,
    done: AtomicBool,
}

impl ScanControl for ChangeAtExactComparison {
    fn on_progress(&self, progress: &ScanProgress) {
        if progress.stage == ProgressStage::ExactComparing
            && progress_path_is(progress, &self.target)
            && !self.done.swap(true, Ordering::AcqRel)
        {
            fs::write(&self.target, b"changed!!").expect("change before exact comparison");
        }
    }
}

#[test]
fn exact_grouping_fails_closed_when_a_file_changes_after_full_hashing() {
    let temporary = TempDir::new().expect("tempdir");
    write_media(temporary.path(), "a.jpg", b"duplicate");
    let second = write_media(temporary.path(), "b.jpg", b"duplicate");
    let control = ChangeAtExactComparison {
        target: second,
        done: AtomicBool::new(false),
    };

    let report = Scanner::default()
        .scan_with_control([temporary.path()], &control)
        .expect("scan returns a fail-closed report");

    assert!(report.duplicate_groups.is_empty());
    assert_eq!(report.status, ScanStatus::Partial);
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.code == ScanIssueCode::ChangedDuringScan));
}

struct ChangeRootAtExactComparison {
    root: PathBuf,
    done: AtomicBool,
}

impl ScanControl for ChangeRootAtExactComparison {
    fn on_progress(&self, progress: &ScanProgress) {
        if progress.stage == ProgressStage::ExactComparing
            && !self.done.swap(true, Ordering::AcqRel)
        {
            write_media(&self.root, "arrived-during-scan.jpg", b"new file");
        }
    }
}

#[test]
fn a_changed_scan_root_interrupts_the_report_and_clears_groups() {
    let temporary = TempDir::new().expect("tempdir");
    write_media(temporary.path(), "a.jpg", b"duplicate");
    write_media(temporary.path(), "b.jpg", b"duplicate");
    let control = ChangeRootAtExactComparison {
        root: temporary.path().to_path_buf(),
        done: AtomicBool::new(false),
    };

    let report = Scanner::default()
        .scan_with_control([temporary.path()], &control)
        .expect("scan returns an interrupted report");

    assert_eq!(report.status, ScanStatus::Interrupted);
    assert!(report.duplicate_groups.is_empty());
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.code == ScanIssueCode::RootChangedDuringScan));
}

#[test]
fn default_exclusions_skip_photo_libraries_quarantine_and_system_metadata() {
    let temporary = TempDir::new().expect("tempdir");
    for directory in ["Family.photoslibrary", ".guiying", ".Spotlight-V100"] {
        let excluded = temporary.path().join(directory);
        fs::create_dir(&excluded).expect("create excluded directory");
        write_media(&excluded, "a.jpg", b"hidden duplicate");
        write_media(&excluded, "b.jpg", b"hidden duplicate");
    }
    write_media(temporary.path(), "visible-a.jpg", b"visible duplicate");
    write_media(temporary.path(), "visible-b.jpg", b"visible duplicate");

    let report = Scanner::default()
        .scan([temporary.path()])
        .expect("scan succeeds");

    assert_eq!(report.stats.excluded_directories_skipped, 3);
    assert_eq!(report.files.len(), 2);
    assert_eq!(report.duplicate_groups.len(), 1);
    assert_eq!(
        report
            .issues
            .iter()
            .filter(|issue| issue.code == ScanIssueCode::DirectoryExcluded)
            .count(),
        3
    );
}

#[test]
fn an_excluded_directory_selected_as_the_root_is_reported_without_descent() {
    let temporary = TempDir::new().expect("tempdir");
    for name in ["Family.photoslibrary", ".guiying"] {
        let excluded_root = temporary.path().join(name);
        fs::create_dir(&excluded_root).expect("create excluded root");
        write_media(&excluded_root, "a.jpg", b"duplicate");
        write_media(&excluded_root, "b.jpg", b"duplicate");

        let report = Scanner::default()
            .scan([&excluded_root])
            .expect("excluded root produces a report");

        assert!(report.files.is_empty());
        assert!(report.duplicate_groups.is_empty());
        assert_eq!(report.stats.excluded_directories_skipped, 1);
        assert!(report
            .issues
            .iter()
            .any(|issue| issue.code == ScanIssueCode::DirectoryExcluded));
    }
}

#[cfg(unix)]
struct ReplaceAncestorAtStage {
    ancestor: PathBuf,
    replacement_target: PathBuf,
    stage: ProgressStage,
    done: AtomicBool,
}

#[cfg(unix)]
impl ScanControl for ReplaceAncestorAtStage {
    fn on_progress(&self, progress: &ScanProgress) {
        if progress.stage == self.stage && !self.done.swap(true, Ordering::AcqRel) {
            use std::os::unix::fs::symlink;

            let moved = self.ancestor.with_file_name("moved-album");
            fs::rename(&self.ancestor, moved).expect("move original ancestor");
            symlink(&self.replacement_target, &self.ancestor)
                .expect("replace ancestor with symlink");
        }
    }
}

#[cfg(unix)]
#[test]
fn scanner_hashing_never_follows_an_ancestor_replaced_by_a_symlink() {
    let temporary = TempDir::new().expect("tempdir");
    let root = temporary.path().join("root");
    let album = root.join("album");
    let outside = temporary.path().join("outside");
    fs::create_dir(&root).expect("root directory");
    fs::create_dir(&album).expect("album directory");
    fs::create_dir(&outside).expect("outside directory");
    write_media(&album, "a.jpg", b"inside duplicate");
    write_media(&album, "b.jpg", b"inside duplicate");
    write_media(&outside, "a.jpg", b"outside payload!");
    write_media(&outside, "b.jpg", b"outside payload!");
    let control = ReplaceAncestorAtStage {
        ancestor: album,
        replacement_target: outside,
        stage: ProgressStage::Sampling,
        done: AtomicBool::new(false),
    };

    let report = Scanner::default()
        .scan_with_control([&root], &control)
        .expect("scanner fails closed");

    assert_eq!(report.stats.bytes_sampled, 0);
    assert!(report.duplicate_groups.is_empty());
    assert_eq!(report.status, ScanStatus::Interrupted);
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.code == ScanIssueCode::FileUnreadable));
}

#[cfg(unix)]
#[test]
fn scanner_exact_comparison_fails_closed_on_an_ancestor_symlink_replacement() {
    let temporary = TempDir::new().expect("tempdir");
    let root = temporary.path().join("root");
    let album = root.join("album");
    let outside = temporary.path().join("outside");
    fs::create_dir(&root).expect("root directory");
    fs::create_dir(&album).expect("album directory");
    fs::create_dir(&outside).expect("outside directory");
    write_media(&album, "a.jpg", b"inside duplicate");
    write_media(&album, "b.jpg", b"inside duplicate");
    write_media(&outside, "a.jpg", b"inside duplicate");
    write_media(&outside, "b.jpg", b"inside duplicate");
    let control = ReplaceAncestorAtStage {
        ancestor: album,
        replacement_target: outside,
        stage: ProgressStage::ExactComparing,
        done: AtomicBool::new(false),
    };

    let report = Scanner::default()
        .scan_with_control([&root], &control)
        .expect("scanner fails closed");

    assert_eq!(report.stats.exact_comparisons, 0);
    assert!(report.duplicate_groups.is_empty());
    assert_eq!(report.status, ScanStatus::Interrupted);
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.code == ScanIssueCode::ExactVerificationFailed));
}

#[cfg(unix)]
#[test]
fn non_utf8_paths_are_lossless_and_json_serializable() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let temporary = TempDir::new().expect("tempdir");
    let raw_name = OsString::from_vec(b"photo-\xff.jpg".to_vec());
    let raw_path = temporary.path().join(raw_name);
    let raw_ref = PathRef::from_path(&raw_path);
    write_media(temporary.path(), "normal.jpg", b"fixture");
    let mut report = Scanner::default()
        .scan([temporary.path()])
        .expect("scan succeeds");
    report.roots[0] = raw_ref.clone();
    report.files[0].path = raw_ref.clone();
    report.issues.push(ScanIssue {
        code: ScanIssueCode::MetadataUnreadable,
        path: raw_ref.clone(),
        detail: "synthetic non-UTF-8 path contract test".to_owned(),
    });

    assert_eq!(raw_ref.to_path_buf().unwrap(), raw_path);
    let json = serde_json::to_string(&report).expect("report serializes");
    let decoded: guiying_core::ScanReport =
        serde_json::from_str(&json).expect("report deserializes");
    assert_eq!(decoded, report);
}

#[test]
fn exact_comparison_handles_equal_and_different_files() {
    let temporary = TempDir::new().expect("tempdir");
    let first = write_media(temporary.path(), "a.mov", b"abcdef");
    let second = write_media(temporary.path(), "b.mov", b"abcdef");
    let third = write_media(temporary.path(), "c.mov", b"abcxef");

    let equal = compare_files_exact(&first, &second, &guiying_core::NoopScanControl)
        .expect("comparison succeeds");
    let different = compare_files_exact(&first, &third, &guiying_core::NoopScanControl)
        .expect("comparison succeeds");

    assert!(equal.identical);
    assert_eq!(equal.bytes_compared, 6);
    assert!(!different.identical);
    assert_eq!(different.bytes_compared, 4);
}

struct ChangeWhileComparing {
    calls: AtomicUsize,
    target: PathBuf,
}

impl ScanControl for ChangeWhileComparing {
    fn is_cancelled(&self) -> bool {
        if self.calls.fetch_add(1, Ordering::AcqRel) == 1 {
            fs::write(&self.target, b"fedcba").expect("change fixture during comparison");
        }
        false
    }
}

#[test]
fn exact_comparison_never_returns_a_result_after_a_concurrent_change() {
    let temporary = TempDir::new().expect("tempdir");
    let first = write_media(temporary.path(), "a.mp4", b"abcdef");
    let second = write_media(temporary.path(), "b.mp4", b"abcdef");
    let control = ChangeWhileComparing {
        calls: AtomicUsize::new(0),
        target: second.clone(),
    };

    let result = compare_files_exact(&first, &second, &control);
    assert!(matches!(
        result,
        Err(VerificationError::ChangedDuringRead(path)) if path == second
    ));
}
