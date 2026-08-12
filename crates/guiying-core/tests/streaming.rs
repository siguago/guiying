use std::convert::Infallible;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use guiying_core::{
    ExactCandidatePair, FileObservationTicket, FreshReadOrigin, NoopScanControl, ScanControl,
    ScanDirective, ScanError, ScanIssueCode, ScanOptions, StreamBatchStatus, StreamEvent,
    StreamLimits, StreamRootKind, StreamScanError, StreamingScanSink, TicketDecodeError,
    STREAM_ENUMERATION_STEP_HARD_MAX, STREAM_INPUT_BATCH_HARD_MAX,
};
use tempfile::TempDir;

fn write_media(directory: &Path, name: &str, contents: &[u8]) -> PathBuf {
    let path = directory.join(name);
    fs::write(&path, contents).expect("write fixture");
    path
}

#[derive(Default)]
struct RecordingSink {
    batches: usize,
    maximum_batch: usize,
    events: Vec<StreamEvent>,
}

impl StreamingScanSink for RecordingSink {
    type Error = Infallible;

    fn write_batch(&mut self, events: &[StreamEvent]) -> Result<(), Self::Error> {
        self.batches += 1;
        self.maximum_batch = self.maximum_batch.max(events.len());
        self.events.extend_from_slice(events);
        Ok(())
    }
}

impl RecordingSink {
    fn file_tickets(&self) -> Vec<FileObservationTicket> {
        self.events
            .iter()
            .filter_map(|event| match event {
                StreamEvent::FileObservation(observation) => Some(observation.ticket.clone()),
                _ => None,
            })
            .collect()
    }

    fn directory_tickets(&self) -> Vec<guiying_core::DirectoryObservationTicket> {
        self.events
            .iter()
            .filter_map(|event| match event {
                StreamEvent::DirectoryObservation(observation) => Some(observation.ticket.clone()),
                _ => None,
            })
            .collect()
    }
}

fn enumeration_observation_keys(events: &[StreamEvent]) -> Vec<(u8, u16, PathBuf)> {
    let mut keys = events
        .iter()
        .filter_map(|event| match event {
            StreamEvent::RootObservation(observation) => Some((
                0,
                observation.root_index,
                observation.path.to_path_buf().expect("local root path"),
            )),
            StreamEvent::DirectoryObservation(observation) => Some((
                1,
                observation.root_index,
                observation
                    .path
                    .to_path_buf()
                    .expect("local directory path"),
            )),
            StreamEvent::FileObservation(observation) => Some((
                2,
                observation.root_index,
                observation.path.to_path_buf().expect("local file path"),
            )),
            _ => None,
        })
        .collect::<Vec<_>>();
    keys.sort();
    keys
}

fn enumeration_finished_events(events: &[StreamEvent]) -> usize {
    events
        .iter()
        .filter(|event| matches!(event, StreamEvent::EnumerationFinished(_)))
        .count()
}

#[test]
fn streaming_rejects_relative_roots_without_resolving_the_working_directory() {
    let relative = PathBuf::from(".");
    let error = match guiying_core::Scanner::default()
        .start_streaming([&relative], StreamLimits::default())
    {
        Ok(_) => panic!("relative streaming root must fail closed"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ScanError::RelativeRoot(path) if path == relative
    ));
}

#[test]
fn enumeration_batches_are_hard_bounded_and_coverage_is_replayed() {
    let temporary = TempDir::new().expect("tempdir");
    for index in 0..300 {
        write_media(
            temporary.path(),
            &format!("photo-{index:04}.jpg"),
            format!("unique-{index}").as_bytes(),
        );
    }
    let mut session = guiying_core::Scanner::default()
        .start_streaming(
            [temporary.path()],
            StreamLimits {
                max_events_per_batch: 7,
                max_bytes_per_batch: 16 * 1024,
            },
        )
        .expect("start session");
    let mut sink = RecordingSink::default();

    let outcome = session
        .enumerate(&mut sink, &NoopScanControl)
        .expect("bounded enumeration");

    assert_eq!(outcome.status, StreamBatchStatus::Completed);
    assert_eq!(outcome.stats.media_files, 300);
    assert!(sink.batches > 1);
    assert!(sink.maximum_batch <= 7);
    assert_eq!(sink.file_tickets().len(), 300);
    let mut directories = sink.directory_tickets();
    directories.sort_by_key(|ticket| *ticket.sort_key());

    let mut coverage_sink = RecordingSink::default();
    for page in directories.chunks(STREAM_INPUT_BATCH_HARD_MAX) {
        session
            .revalidate_directory_batch(page, &mut coverage_sink, &NoopScanControl)
            .expect("revalidate directory page");
    }
    let coverage = session
        .finalize_coverage(&mut coverage_sink, &NoopScanControl)
        .expect("finalize coverage");
    assert_eq!(coverage.status, StreamBatchStatus::Completed);
    assert!(coverage_sink
        .events
        .iter()
        .any(|event| matches!(event, StreamEvent::CoverageVerified(_))));
}

#[test]
fn compatibility_enumerate_reports_every_entry_consumed_across_internal_steps() {
    for entry_count in [65_u64, 128, 129] {
        let temporary = TempDir::new().expect("tempdir");
        for index in 0..entry_count {
            write_media(
                temporary.path(),
                &format!("photo-{index:04}.jpg"),
                b"fixture",
            );
        }
        let mut session = guiying_core::Scanner::default()
            .start_streaming([temporary.path()], StreamLimits::default())
            .expect("start session");
        let mut sink = RecordingSink::default();

        let outcome = session
            .enumerate(&mut sink, &NoopScanControl)
            .expect("compatibility enumeration");

        assert_eq!(outcome.status, StreamBatchStatus::Completed);
        assert_eq!(outcome.consumed, entry_count);
        assert_eq!(outcome.stats.entries_seen, entry_count);
        assert_eq!(sink.file_tickets().len() as u64, entry_count);
        assert_eq!(enumeration_finished_events(&sink.events), 1);
    }
}

struct AlwaysPause;

impl ScanControl for AlwaysPause {
    fn directive(&self) -> ScanDirective {
        ScanDirective::Pause
    }
}

#[test]
fn paused_step_resumes_without_missing_or_repeating_enumeration_events() {
    let temporary = TempDir::new().expect("tempdir");
    let entry_count = (STREAM_ENUMERATION_STEP_HARD_MAX * 2 + 1) as u64;
    for index in 0..entry_count {
        write_media(
            temporary.path(),
            &format!("photo-{index:04}.jpg"),
            b"fixture",
        );
    }

    let mut baseline_session = guiying_core::Scanner::default()
        .start_streaming([temporary.path()], StreamLimits::default())
        .expect("baseline session");
    let mut baseline_sink = RecordingSink::default();
    let baseline = baseline_session
        .enumerate(&mut baseline_sink, &NoopScanControl)
        .expect("baseline enumeration");

    let mut stepped_session = guiying_core::Scanner::default()
        .start_streaming([temporary.path()], StreamLimits::default())
        .expect("stepped session");
    let mut stepped_sink = RecordingSink::default();
    let first = stepped_session
        .enumerate_step(&mut stepped_sink, &NoopScanControl)
        .expect("first bounded step");
    assert_eq!(first.status, StreamBatchStatus::InProgress);
    assert_eq!(first.consumed, STREAM_ENUMERATION_STEP_HARD_MAX as u64);

    let events_before_pause = stepped_sink.events.len();
    let paused = stepped_session
        .enumerate_step(&mut stepped_sink, &AlwaysPause)
        .expect("cooperative pause");
    assert_eq!(paused.status, StreamBatchStatus::Paused);
    assert_eq!(paused.consumed, 0);
    assert_eq!(stepped_sink.events.len(), events_before_pause);

    let resumed = stepped_session
        .resume_enumeration(&mut stepped_sink, &NoopScanControl)
        .expect("resume enumeration");
    assert_eq!(resumed.status, StreamBatchStatus::Completed);
    assert_eq!(resumed.stats, baseline.stats);
    assert_eq!(
        resumed.directory_observations,
        baseline.directory_observations
    );
    assert_eq!(
        enumeration_observation_keys(&stepped_sink.events),
        enumeration_observation_keys(&baseline_sink.events)
    );
    assert_eq!(stepped_sink.file_tickets().len() as u64, entry_count);
    let mut unique_files = stepped_sink
        .events
        .iter()
        .filter_map(|event| match event {
            StreamEvent::FileObservation(observation) => {
                Some(observation.path.to_path_buf().expect("local file path"))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    unique_files.sort();
    unique_files.dedup();
    assert_eq!(unique_files.len() as u64, entry_count);
    assert_eq!(enumeration_finished_events(&stepped_sink.events), 1);
}

#[test]
fn root_observation_exposes_descriptor_identity_for_volume_binding() {
    let temporary = TempDir::new().expect("tempdir");
    write_media(temporary.path(), "photo.jpg", b"fixture");
    let mut session = guiying_core::Scanner::default()
        .start_streaming([temporary.path()], StreamLimits::default())
        .expect("start session");
    let mut sink = RecordingSink::default();
    session
        .enumerate(&mut sink, &NoopScanControl)
        .expect("enumerate");

    let root = sink
        .events
        .iter()
        .find_map(|event| match event {
            StreamEvent::RootObservation(root) => Some(root),
            _ => None,
        })
        .expect("root observation");
    let root_directory = sink
        .events
        .iter()
        .find_map(|event| match event {
            StreamEvent::DirectoryObservation(directory) if directory.path == root.path => {
                Some(directory)
            }
            _ => None,
        })
        .expect("root directory observation");
    assert_eq!(root.root_index, 0);
    assert_eq!(root.kind, StreamRootKind::Directory);
    assert_eq!(root_directory.root_index, 0);
    assert_eq!(
        root_directory.root_relative_path.to_path_buf().unwrap(),
        PathBuf::new()
    );
    assert_eq!(root.source_signature, root_directory.source_signature);
    #[cfg(unix)]
    {
        assert!(root.file_id.is_some());
        assert!(root.mode.is_some());
        assert!(root.change_time.is_some());
    }
    #[cfg(target_os = "macos")]
    assert!(root.generation.is_some());
}

#[test]
fn multiple_roots_with_the_same_suffix_keep_distinct_root_indices() {
    let temporary = TempDir::new().expect("tempdir");
    let first = temporary.path().join("a-root");
    let second = temporary.path().join("b-root");
    fs::create_dir(&first).expect("first root");
    fs::create_dir(&second).expect("second root");
    fs::create_dir(first.join("same")).expect("first suffix");
    fs::create_dir(second.join("same")).expect("second suffix");
    write_media(&first.join("same"), "photo.jpg", b"first");
    write_media(&second.join("same"), "photo.jpg", b"second");
    let mut session = guiying_core::Scanner::default()
        .start_streaming([&first, &second], StreamLimits::default())
        .expect("start session");
    let mut sink = RecordingSink::default();
    session
        .enumerate(&mut sink, &NoopScanControl)
        .expect("enumerate roots");
    let observations: Vec<_> = sink
        .events
        .iter()
        .filter_map(|event| match event {
            StreamEvent::FileObservation(observation) => Some(observation),
            _ => None,
        })
        .collect();

    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].root_index, 0);
    assert_eq!(observations[1].root_index, 1);
    assert_eq!(
        observations[0].root_relative_path.to_path_buf().unwrap(),
        PathBuf::from("same").join("photo.jpg")
    );
    assert_eq!(
        observations[1].root_relative_path,
        observations[0].root_relative_path
    );
    assert_ne!(
        observations[0].source_signature,
        observations[1].source_signature
    );
    assert_ne!(
        observations[0].ticket.as_bytes(),
        observations[1].ticket.as_bytes()
    );
}

#[test]
fn a_nonmedia_file_root_does_not_shift_later_root_ticket_indices() {
    let temporary = TempDir::new().expect("tempdir");
    let nonmedia = write_media(temporary.path(), "00-note.txt", b"not media");
    let media_root = temporary.path().join("zz-media");
    fs::create_dir(&media_root).expect("media root");
    write_media(&media_root, "photo.jpg", b"media fixture");
    let mut session = guiying_core::Scanner::default()
        .start_streaming([&nonmedia, &media_root], StreamLimits::default())
        .expect("start session");
    let mut enumeration = RecordingSink::default();
    let outcome = session
        .enumerate(&mut enumeration, &NoopScanControl)
        .expect("enumerate");
    assert_eq!(outcome.status, StreamBatchStatus::Completed);
    let observation = enumeration
        .events
        .iter()
        .find_map(|event| match event {
            StreamEvent::FileObservation(observation) => Some(observation),
            _ => None,
        })
        .expect("media observation");
    assert_eq!(observation.root_index, 1);
    let mut hash_sink = RecordingSink::default();
    let hashed = session
        .full_hash_batch(
            &[observation.ticket.clone()],
            &mut hash_sink,
            &NoopScanControl,
        )
        .expect("later root ticket opens correct root");
    assert_eq!(hashed.completed, 1);
}

#[test]
fn selected_root_aliases_are_bounded_and_make_coverage_partial() {
    let temporary = TempDir::new().expect("tempdir");
    let root = temporary.path().join("root");
    let lexical_anchor = root.join("anchor");
    fs::create_dir(&root).expect("root");
    fs::create_dir(&lexical_anchor).expect("anchor");
    write_media(&root, "photo.jpg", b"fixture");
    let alias = lexical_anchor.join("..");
    let mut session = guiying_core::Scanner::default()
        .start_streaming([&root, &alias], StreamLimits::default())
        .expect("start session");
    let mut sink = RecordingSink::default();

    let outcome = session
        .enumerate(&mut sink, &NoopScanControl)
        .expect("enumerate aliases");

    assert_eq!(outcome.status, StreamBatchStatus::Partial);
    assert_eq!(sink.file_tickets().len(), 1);
    assert_eq!(
        sink.events
            .iter()
            .filter(|event| matches!(event, StreamEvent::RootObservation(_)))
            .count(),
        2
    );
    assert!(sink.events.iter().any(|event| matches!(
        event,
        StreamEvent::Issue(issue)
            if issue.code == ScanIssueCode::DirectoryIdentityAlreadyVisited
    )));
}

#[derive(Debug, Eq, PartialEq)]
struct SinkRefusal;

impl std::fmt::Display for SinkRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("refused")
    }
}

impl std::error::Error for SinkRefusal {}

struct RefusingSink {
    calls: usize,
}

impl StreamingScanSink for RefusingSink {
    type Error = SinkRefusal;

    fn write_batch(&mut self, _events: &[StreamEvent]) -> Result<(), Self::Error> {
        self.calls += 1;
        Err(SinkRefusal)
    }
}

#[test]
fn sink_failure_stops_immediately_and_poisons_the_session() {
    let temporary = TempDir::new().expect("tempdir");
    for index in 0..20 {
        write_media(temporary.path(), &format!("photo-{index}.jpg"), b"fixture");
    }
    let mut session = guiying_core::Scanner::default()
        .start_streaming(
            [temporary.path()],
            StreamLimits {
                max_events_per_batch: 1,
                max_bytes_per_batch: 16 * 1024,
            },
        )
        .expect("start session");
    let mut sink = RefusingSink { calls: 0 };

    let error = session
        .enumerate(&mut sink, &NoopScanControl)
        .expect_err("sink refusal must fail closed");
    assert!(matches!(error, StreamScanError::Sink(SinkRefusal)));
    assert_eq!(sink.calls, 1);

    let error = session
        .enumerate(&mut sink, &NoopScanControl)
        .expect_err("poisoned session cannot resume");
    assert!(matches!(error, StreamScanError::InvalidState(_)));
}

fn enumerated_session(
    directory: &Path,
) -> (
    guiying_core::StreamingScanSession,
    Vec<FileObservationTicket>,
) {
    let (session, sink) = enumerated_session_with_events(directory);
    (session, sink.file_tickets())
}

fn enumerated_session_with_events(
    directory: &Path,
) -> (guiying_core::StreamingScanSession, RecordingSink) {
    let mut session = guiying_core::Scanner::default()
        .start_streaming([directory], StreamLimits::default())
        .expect("start session");
    let mut sink = RecordingSink::default();
    session
        .enumerate(&mut sink, &NoopScanControl)
        .expect("enumerate");
    (session, sink)
}

#[test]
fn full_hash_evidence_is_fresh_sealed_and_eof_verified() {
    let temporary = TempDir::new().expect("tempdir");
    let contents = b"fresh exact bytes";
    write_media(temporary.path(), "photo.jpg", contents);
    let (mut session, enumeration) = enumerated_session_with_events(temporary.path());
    let tickets = enumeration.file_tickets();
    let observation_signature = enumeration
        .events
        .iter()
        .find_map(|event| match event {
            StreamEvent::FileObservation(observation) => Some(observation.source_signature),
            _ => None,
        })
        .expect("file observation");
    let mut sink = RecordingSink::default();

    let outcome = session
        .full_hash_batch(&tickets, &mut sink, &NoopScanControl)
        .expect("fresh hash");

    assert_eq!(outcome.completed, 1);
    let evidence = sink
        .events
        .iter()
        .find_map(|event| match event {
            StreamEvent::FreshFingerprint(evidence) => Some(evidence),
            _ => None,
        })
        .expect("fingerprint event");
    assert_eq!(
        evidence.read_origin(),
        FreshReadOrigin::CurrentSessionFullHash
    );
    assert_eq!(evidence.digest(), blake3::hash(contents).as_bytes());
    assert_eq!(evidence.expected_length(), contents.len() as u64);
    assert_eq!(evidence.bytes_read(), contents.len() as u64);
    assert!(evidence.eof_verified());
    assert_eq!(
        evidence.before_source_signature(),
        evidence.after_source_signature()
    );
    assert_eq!(evidence.before_source_signature(), &observation_signature);
    assert_eq!(evidence.session_id(), session.session_id());
}

#[test]
fn sample_evidence_uses_the_same_authenticated_observation_signature() {
    let temporary = TempDir::new().expect("tempdir");
    write_media(temporary.path(), "photo.jpg", b"sample fixture bytes");
    let (mut session, enumeration) = enumerated_session_with_events(temporary.path());
    let observation = enumeration
        .events
        .iter()
        .find_map(|event| match event {
            StreamEvent::FileObservation(observation) => Some(observation),
            _ => None,
        })
        .expect("file observation");
    let mut sink = RecordingSink::default();

    let outcome = session
        .sample_batch(&[observation.ticket.clone()], &mut sink, &NoopScanControl)
        .expect("fresh sample");

    assert_eq!(outcome.completed, 1);
    let evidence = sink
        .events
        .iter()
        .find_map(|event| match event {
            StreamEvent::FreshFingerprint(evidence) => Some(evidence),
            _ => None,
        })
        .expect("sample evidence");
    assert_eq!(
        evidence.read_origin(),
        FreshReadOrigin::CurrentSessionSample
    );
    assert!(!evidence.eof_verified());
    assert_eq!(
        evidence.before_source_signature(),
        &observation.source_signature
    );
    assert_eq!(
        evidence.after_source_signature(),
        &observation.source_signature
    );
}

#[test]
fn exact_comparison_emits_full_eof_and_digest_evidence() {
    let temporary = TempDir::new().expect("tempdir");
    let contents = b"duplicate payload";
    write_media(temporary.path(), "a.jpg", contents);
    write_media(temporary.path(), "b.jpg", contents);
    let (mut session, enumeration) = enumerated_session_with_events(temporary.path());
    let tickets = enumeration.file_tickets();
    let observation_signatures: Vec<_> = enumeration
        .events
        .iter()
        .filter_map(|event| match event {
            StreamEvent::FileObservation(observation) => Some(observation.source_signature),
            _ => None,
        })
        .collect();
    let pair = ExactCandidatePair::new(tickets[0].clone(), tickets[1].clone());
    let mut sink = RecordingSink::default();

    let outcome = session
        .exact_compare_batch(&[pair], &mut sink, &NoopScanControl)
        .expect("exact comparison");

    assert_eq!(outcome.completed, 1);
    let evidence = sink
        .events
        .iter()
        .find_map(|event| match event {
            StreamEvent::ExactComparison(evidence) => Some(evidence),
            _ => None,
        })
        .expect("exact evidence");
    assert!(evidence.identical());
    assert!(evidence.eof_verified());
    assert_eq!(evidence.bytes_compared(), contents.len() as u64);
    assert_eq!(
        evidence.left_digest(),
        Some(blake3::hash(contents).as_bytes())
    );
    assert_eq!(
        evidence.right_digest(),
        Some(blake3::hash(contents).as_bytes())
    );
    assert_eq!(
        evidence.left_before_source_signature(),
        evidence.left_after_source_signature()
    );
    assert_eq!(
        evidence.right_before_source_signature(),
        evidence.right_after_source_signature()
    );
    assert_eq!(
        evidence.left_before_source_signature(),
        &observation_signatures[0]
    );
    assert_eq!(
        evidence.right_before_source_signature(),
        &observation_signatures[1]
    );
}

#[test]
fn a_tampered_ticket_is_rejected_before_any_read_proof() {
    let temporary = TempDir::new().expect("tempdir");
    write_media(temporary.path(), "photo.jpg", b"fixture");
    let (mut session, tickets) = enumerated_session(temporary.path());
    let mut bytes = tickets[0].as_bytes().to_vec();
    let position = bytes.len() - 40;
    bytes[position] ^= 0x40;
    let tampered = FileObservationTicket::from_bytes(&bytes).expect("structurally valid ticket");
    let mut sink = RecordingSink::default();

    let error = session
        .full_hash_batch(&[tampered], &mut sink, &NoopScanControl)
        .expect_err("MAC mismatch must fail closed");

    assert!(matches!(
        error,
        StreamScanError::Ticket(TicketDecodeError::AuthenticationFailed)
    ));
    assert!(!sink
        .events
        .iter()
        .any(|event| matches!(event, StreamEvent::FreshFingerprint(_))));
}

#[test]
fn a_ticket_cannot_be_replayed_in_another_live_session() {
    let temporary = TempDir::new().expect("tempdir");
    write_media(temporary.path(), "photo.jpg", b"fixture");
    let (_first_session, first_tickets) = enumerated_session(temporary.path());
    let (mut second_session, _) = enumerated_session(temporary.path());
    let mut sink = RecordingSink::default();

    let error = second_session
        .full_hash_batch(&first_tickets, &mut sink, &NoopScanControl)
        .expect_err("cross-session replay must fail closed");

    assert!(matches!(
        error,
        StreamScanError::Ticket(TicketDecodeError::WrongSession)
    ));
}

#[test]
fn caller_input_batches_have_a_separate_hard_limit() {
    let temporary = TempDir::new().expect("tempdir");
    write_media(temporary.path(), "photo.jpg", b"fixture");
    let (mut session, tickets) = enumerated_session(temporary.path());
    let oversized = vec![tickets[0].clone(); STREAM_INPUT_BATCH_HARD_MAX + 1];
    let mut sink = RecordingSink::default();

    let error = session
        .full_hash_batch(&oversized, &mut sink, &NoopScanControl)
        .expect_err("oversized input must be rejected before reads");

    assert!(matches!(error, StreamScanError::InputBatchTooLarge { .. }));
    assert!(sink.events.is_empty());
}

#[test]
fn a_file_changed_after_enumeration_never_produces_fresh_evidence() {
    let temporary = TempDir::new().expect("tempdir");
    let path = write_media(temporary.path(), "photo.jpg", b"original");
    let (mut session, tickets) = enumerated_session(temporary.path());
    fs::write(path, b"changed!").expect("change fixture");
    let mut sink = RecordingSink::default();

    let outcome = session
        .full_hash_batch(&tickets, &mut sink, &NoopScanControl)
        .expect("changed files are per-entry failures");

    assert_eq!(outcome.failed, 1);
    assert!(!sink
        .events
        .iter()
        .any(|event| matches!(event, StreamEvent::FreshFingerprint(_))));
    assert!(sink.events.iter().any(|event| matches!(
        event,
        StreamEvent::Issue(issue) if issue.code == ScanIssueCode::ChangedDuringScan
    )));
}

#[cfg(unix)]
#[test]
fn changing_a_public_identity_field_invalidates_the_old_ticket() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = TempDir::new().expect("tempdir");
    let path = write_media(temporary.path(), "photo.jpg", b"fixture");
    let (mut session, enumeration) = enumerated_session_with_events(temporary.path());
    let observation = enumeration
        .events
        .iter()
        .find_map(|event| match event {
            StreamEvent::FileObservation(observation) => Some(observation),
            _ => None,
        })
        .expect("file observation");
    assert!(observation.mode.is_some());
    assert!(observation.change_time.is_some());
    assert!(observation.allocated_size.is_some());
    let mut permissions = fs::metadata(&path).expect("metadata").permissions();
    permissions.set_mode(permissions.mode() ^ 0o100);
    fs::set_permissions(&path, permissions).expect("change mode");
    let mut sink = RecordingSink::default();

    let outcome = session
        .full_hash_batch(&[observation.ticket.clone()], &mut sink, &NoopScanControl)
        .expect("changed identity is a per-file issue");

    assert_eq!(outcome.failed, 1);
    assert!(!sink
        .events
        .iter()
        .any(|event| matches!(event, StreamEvent::FreshFingerprint(_))));
}

struct AlreadyCancelled;

impl ScanControl for AlreadyCancelled {
    fn is_cancelled(&self) -> bool {
        true
    }
}

struct CancelledAndPaused;

impl ScanControl for CancelledAndPaused {
    fn is_cancelled(&self) -> bool {
        true
    }

    fn directive(&self) -> ScanDirective {
        ScanDirective::Pause
    }
}

#[test]
fn cancellation_is_terminal_and_emits_no_file_observation() {
    let temporary = TempDir::new().expect("tempdir");
    write_media(temporary.path(), "photo.jpg", b"fixture");
    let mut session = guiying_core::Scanner::default()
        .start_streaming([temporary.path()], StreamLimits::default())
        .expect("start session");
    let mut sink = RecordingSink::default();

    let outcome = session
        .enumerate(&mut sink, &AlreadyCancelled)
        .expect("cooperative cancellation");

    assert_eq!(outcome.status, StreamBatchStatus::Cancelled);
    assert!(sink.file_tickets().is_empty());
}

#[test]
fn cancellation_dominates_a_simultaneous_pause_and_cannot_resume() {
    let temporary = TempDir::new().expect("tempdir");
    write_media(temporary.path(), "photo.jpg", b"fixture");
    let mut session = guiying_core::Scanner::default()
        .start_streaming([temporary.path()], StreamLimits::default())
        .expect("start session");
    let mut sink = RecordingSink::default();

    let outcome = session
        .enumerate_step(&mut sink, &CancelledAndPaused)
        .expect("cancellation wins at the safe point");

    assert_eq!(outcome.status, StreamBatchStatus::Cancelled);
    assert!(sink.file_tickets().is_empty());
    let error = session
        .resume_enumeration(&mut sink, &NoopScanControl)
        .expect_err("cancelled traversal cannot resume");
    assert!(matches!(error, StreamScanError::InvalidState(_)));
}

struct CancelFreshRead {
    checks: AtomicUsize,
}

impl ScanControl for CancelFreshRead {
    fn is_cancelled(&self) -> bool {
        self.checks.fetch_add(1, Ordering::AcqRel) >= 1
    }
}

#[test]
fn cancellation_during_a_fresh_read_emits_no_partial_proof() {
    let temporary = TempDir::new().expect("tempdir");
    write_media(temporary.path(), "photo.jpg", &[0x5a; 4096]);
    let (mut session, tickets) = enumerated_session(temporary.path());
    let control = CancelFreshRead {
        checks: AtomicUsize::new(0),
    };
    let mut sink = RecordingSink::default();

    let outcome = session
        .full_hash_batch(&tickets, &mut sink, &control)
        .expect("cooperative read cancellation");

    assert_eq!(outcome.status, StreamBatchStatus::Cancelled);
    assert!(!sink
        .events
        .iter()
        .any(|event| matches!(event, StreamEvent::FreshFingerprint(_))));
    let error = session
        .full_hash_batch(&tickets, &mut sink, &NoopScanControl)
        .expect_err("cancelled session cannot resume reads");
    assert!(matches!(error, StreamScanError::InvalidState(_)));
}

#[cfg(unix)]
#[test]
fn hashing_never_follows_an_enumerated_ancestor_replaced_by_a_symlink() {
    use std::os::unix::fs::symlink;

    let temporary = TempDir::new().expect("tempdir");
    let root = temporary.path().join("root");
    let album = root.join("album");
    let outside = temporary.path().join("outside");
    fs::create_dir(&root).expect("root");
    fs::create_dir(&album).expect("album");
    fs::create_dir(&outside).expect("outside");
    write_media(&album, "photo.jpg", b"inside payload");
    write_media(&outside, "photo.jpg", b"outside data!!");
    let (mut session, tickets) = enumerated_session(&root);
    fs::rename(&album, root.join("moved-album")).expect("move album");
    symlink(&outside, &album).expect("replace with symlink");
    let mut sink = RecordingSink::default();

    let outcome = session
        .full_hash_batch(&tickets, &mut sink, &NoopScanControl)
        .expect("ancestor replacement is a bounded issue");

    assert_eq!(outcome.failed, 1);
    assert!(!sink
        .events
        .iter()
        .any(|event| matches!(event, StreamEvent::FreshFingerprint(_))));
}

#[test]
fn coverage_finalization_consumes_no_caller_supplied_items() {
    let temporary = TempDir::new().expect("tempdir");
    let album = temporary.path().join("album");
    fs::create_dir(&album).expect("album");
    write_media(&album, "photo.jpg", b"fixture");
    let mut session = guiying_core::Scanner::default()
        .start_streaming([temporary.path()], StreamLimits::default())
        .expect("start session");
    let mut enumeration = RecordingSink::default();
    session
        .enumerate(&mut enumeration, &NoopScanControl)
        .expect("enumerate");
    let mut directories = enumeration.directory_tickets();
    directories.sort_by_key(|ticket| *ticket.sort_key());
    let mut coverage_sink = RecordingSink::default();

    let replay = session
        .revalidate_directory_batch(&directories, &mut coverage_sink, &NoopScanControl)
        .expect("revalidate directory tickets");
    assert_eq!(replay.consumed, directories.len() as u64);
    let finalization = session
        .finalize_coverage(&mut coverage_sink, &NoopScanControl)
        .expect("finalize coverage");

    assert_eq!(finalization.status, StreamBatchStatus::Completed);
    assert_eq!(finalization.consumed, 0);
}

#[test]
fn changed_directory_coverage_interrupts_without_a_coverage_seal() {
    let temporary = TempDir::new().expect("tempdir");
    let album = temporary.path().join("album");
    fs::create_dir(&album).expect("album");
    write_media(&album, "photo.jpg", b"fixture");
    let mut session = guiying_core::Scanner::default()
        .start_streaming([temporary.path()], StreamLimits::default())
        .expect("start session");
    let mut enumeration = RecordingSink::default();
    session
        .enumerate(&mut enumeration, &NoopScanControl)
        .expect("enumerate");
    write_media(&album, "arrived-late.jpg", b"late fixture");
    let mut directories = enumeration.directory_tickets();
    directories.sort_by_key(|ticket| *ticket.sort_key());
    let mut coverage_sink = RecordingSink::default();

    let mut prior_failures = 0_u64;
    for page in directories.chunks(1) {
        let outcome = session
            .revalidate_directory_batch(page, &mut coverage_sink, &NoopScanControl)
            .expect("changed directory is bounded evidence");
        prior_failures += outcome.failed;
    }
    assert_eq!(prior_failures, 1);
    let finalization = session
        .finalize_coverage(&mut coverage_sink, &NoopScanControl)
        .expect("coverage finalization returns interrupted");
    assert_eq!(finalization.status, StreamBatchStatus::Interrupted);
    assert_eq!(finalization.failed, prior_failures);
    assert!(!coverage_sink
        .events
        .iter()
        .any(|event| matches!(event, StreamEvent::CoverageVerified(_))));
}

#[cfg(unix)]
#[test]
fn replacing_the_selected_root_is_detected_at_coverage_finalization() {
    use std::os::unix::fs::symlink;

    let temporary = TempDir::new().expect("tempdir");
    let root = temporary.path().join("root");
    let outside = temporary.path().join("outside");
    fs::create_dir(&root).expect("root");
    fs::create_dir(&outside).expect("outside");
    write_media(&root, "photo.jpg", b"inside");
    write_media(&outside, "photo.jpg", b"outside");
    let mut session = guiying_core::Scanner::default()
        .start_streaming([&root], StreamLimits::default())
        .expect("start session");
    let mut enumeration = RecordingSink::default();
    session
        .enumerate(&mut enumeration, &NoopScanControl)
        .expect("enumerate");
    fs::rename(&root, temporary.path().join("moved-root")).expect("move root");
    symlink(&outside, &root).expect("replace root");
    let mut directories = enumeration.directory_tickets();
    directories.sort_by_key(|ticket| *ticket.sort_key());
    let mut coverage_sink = RecordingSink::default();
    session
        .revalidate_directory_batch(&directories, &mut coverage_sink, &NoopScanControl)
        .expect("descriptor-bound directory remains the original");

    let finalization = session
        .finalize_coverage(&mut coverage_sink, &NoopScanControl)
        .expect("lexical root replacement is interrupted");
    assert_eq!(finalization.status, StreamBatchStatus::Interrupted);
    assert!(coverage_sink.events.iter().any(|event| matches!(
        event,
        StreamEvent::Issue(issue) if issue.code == ScanIssueCode::RootChangedDuringScan
    )));
}

#[test]
fn partial_enumeration_cannot_mint_a_complete_coverage_seal() {
    let temporary = TempDir::new().expect("tempdir");
    let one = temporary.path().join("one");
    let two = one.join("two");
    fs::create_dir_all(&two).expect("deep tree");
    write_media(&two, "photo.jpg", b"fixture");
    let scanner = guiying_core::Scanner::new(ScanOptions {
        max_directory_depth: 1,
        ..ScanOptions::default()
    })
    .expect("scanner");
    let mut session = scanner
        .start_streaming([temporary.path()], StreamLimits::default())
        .expect("start session");
    let mut enumeration = RecordingSink::default();
    let outcome = session
        .enumerate(&mut enumeration, &NoopScanControl)
        .expect("partial enumeration");
    assert_eq!(outcome.status, StreamBatchStatus::Partial);
    let mut directories = enumeration.directory_tickets();
    directories.sort_by_key(|ticket| *ticket.sort_key());
    let mut coverage_sink = RecordingSink::default();
    session
        .revalidate_directory_batch(&directories, &mut coverage_sink, &NoopScanControl)
        .expect("revalidate observed subset");

    let finalization = session
        .finalize_coverage(&mut coverage_sink, &NoopScanControl)
        .expect("partial coverage remains partial");
    assert_eq!(finalization.status, StreamBatchStatus::Partial);
    assert!(!coverage_sink
        .events
        .iter()
        .any(|event| matches!(event, StreamEvent::CoverageVerified(_))));
}

#[test]
fn duplicate_or_out_of_order_directory_replay_poisons_coverage() {
    let temporary = TempDir::new().expect("tempdir");
    let album = temporary.path().join("album");
    fs::create_dir(&album).expect("album");
    write_media(&album, "photo.jpg", b"fixture");
    let mut session = guiying_core::Scanner::default()
        .start_streaming([temporary.path()], StreamLimits::default())
        .expect("start session");
    let mut enumeration = RecordingSink::default();
    session
        .enumerate(&mut enumeration, &NoopScanControl)
        .expect("enumerate");
    let mut directories = enumeration.directory_tickets();
    directories.sort_by_key(|ticket| *ticket.sort_key());
    directories.reverse();
    let mut sink = RecordingSink::default();

    let error = session
        .revalidate_directory_batch(&directories, &mut sink, &NoopScanControl)
        .expect_err("out-of-order replay must fail closed");
    assert!(matches!(error, StreamScanError::DirectoryTicketOrder));
    let error = session
        .finalize_coverage(&mut sink, &NoopScanControl)
        .expect_err("poisoned coverage cannot finalize");
    assert!(matches!(error, StreamScanError::InvalidState(_)));
}

#[cfg(all(unix, not(target_vendor = "apple")))]
#[test]
fn non_utf8_observation_paths_and_tickets_round_trip_losslessly() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let temporary = TempDir::new().expect("tempdir");
    let path = temporary
        .path()
        .join(OsString::from_vec(b"photo-\xff.jpg".to_vec()));
    fs::write(&path, b"fixture").expect("write non-UTF8 fixture");
    let mut session = guiying_core::Scanner::default()
        .start_streaming([temporary.path()], StreamLimits::default())
        .expect("start session");
    let mut sink = RecordingSink::default();
    session
        .enumerate(&mut sink, &NoopScanControl)
        .expect("enumerate");

    let observation = sink
        .events
        .iter()
        .find_map(|event| match event {
            StreamEvent::FileObservation(observation) => Some(observation),
            _ => None,
        })
        .expect("observation");
    assert_eq!(observation.path.to_path_buf().unwrap(), path);
    assert_eq!(observation.root_index, 0);
    assert_eq!(
        observation.root_relative_path.to_path_buf().unwrap(),
        PathBuf::from(OsString::from_vec(b"photo-\xff.jpg".to_vec()))
    );
    let restored = FileObservationTicket::from_bytes(observation.ticket.as_bytes())
        .expect("restore opaque ticket");
    let mut hash_sink = RecordingSink::default();
    let outcome = session
        .full_hash_batch(&[restored], &mut hash_sink, &NoopScanControl)
        .expect("hash non-UTF8 path");
    assert_eq!(outcome.completed, 1);
}

struct ShrinkDuringRead {
    path: PathBuf,
    checks: AtomicUsize,
}

impl ScanControl for ShrinkDuringRead {
    fn is_cancelled(&self) -> bool {
        if self.checks.fetch_add(1, Ordering::AcqRel) == 1 {
            fs::write(&self.path, b"x").expect("shrink fixture");
        }
        false
    }
}

#[test]
fn a_short_or_changed_read_cannot_emit_an_eof_proof() {
    let temporary = TempDir::new().expect("tempdir");
    let path = write_media(temporary.path(), "photo.jpg", &[0x5a; 4096]);
    let scanner = guiying_core::Scanner::new(ScanOptions {
        read_buffer_bytes: 32,
        ..ScanOptions::default()
    })
    .expect("scanner");
    let mut session = scanner
        .start_streaming([temporary.path()], StreamLimits::default())
        .expect("start session");
    let mut enumeration = RecordingSink::default();
    session
        .enumerate(&mut enumeration, &NoopScanControl)
        .expect("enumerate");
    let control = ShrinkDuringRead {
        path,
        checks: AtomicUsize::new(0),
    };
    let mut sink = RecordingSink::default();

    let outcome = session
        .full_hash_batch(&enumeration.file_tickets(), &mut sink, &control)
        .expect("short read is a per-file failure");

    assert_eq!(outcome.failed, 1);
    assert!(!sink.events.iter().any(|event| matches!(
        event,
        StreamEvent::FreshFingerprint(evidence) if evidence.eof_verified()
    )));
}

#[test]
fn streaming_deduplicates_directory_identities_across_the_whole_session() {
    let temporary = TempDir::new().expect("tempdir");
    let parent = temporary.path().join("parent");
    let child = parent.join("child");
    fs::create_dir(&parent).expect("create parent");
    fs::create_dir(&child).expect("create child");
    write_media(&child, "photo.jpg", b"one media file");

    // `child` is already enumerated while walking `parent`; selecting it again
    // as its own root must be skipped by the session-global identity set,
    // matching the batch scanner's global de-duplication semantics.
    let mut session = guiying_core::Scanner::default()
        .start_streaming([parent.as_path(), child.as_path()], StreamLimits::default())
        .expect("start session");
    let mut sink = RecordingSink::default();
    let outcome = session
        .enumerate(&mut sink, &NoopScanControl)
        .expect("bounded enumeration");

    assert_eq!(outcome.status, StreamBatchStatus::Partial);
    assert_eq!(outcome.stats.directory_identity_revisits_skipped, 1);
    let file_observations = sink
        .events
        .iter()
        .filter(|event| matches!(event, StreamEvent::FileObservation(_)))
        .count();
    assert_eq!(file_observations, 1);
    let revisit_issues = sink
        .events
        .iter()
        .filter(|event| {
            matches!(
                event,
                StreamEvent::Issue(issue)
                    if issue.code == ScanIssueCode::DirectoryIdentityAlreadyVisited
            )
        })
        .count();
    assert_eq!(revisit_issues, 1);

    // The skipped duplicate root emitted no directory ticket, so replaying the
    // enumerated ticket set still matches exactly, but the coverage decision
    // must stay `Partial` instead of granting a complete seal.
    let mut directories = sink.directory_tickets();
    directories.sort_by_key(|ticket| *ticket.sort_key());
    let mut coverage_sink = RecordingSink::default();
    for page in directories.chunks(STREAM_INPUT_BATCH_HARD_MAX) {
        session
            .revalidate_directory_batch(page, &mut coverage_sink, &NoopScanControl)
            .expect("revalidate directory page");
    }
    let coverage = session
        .finalize_coverage(&mut coverage_sink, &NoopScanControl)
        .expect("finalize coverage");
    assert_eq!(coverage.status, StreamBatchStatus::Partial);
    assert!(!coverage_sink
        .events
        .iter()
        .any(|event| matches!(event, StreamEvent::CoverageVerified(_))));
}
