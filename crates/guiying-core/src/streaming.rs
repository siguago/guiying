//! Bounded, current-process scanning primitives for the persistent runtime.
//!
//! This module deliberately separates filesystem reads from durable storage.
//! A synchronous sink provides backpressure: the scanner does not perform the
//! next filesystem operation until the current bounded batch is accepted.
//! Tickets may be persisted as opaque bytes, but are authenticated with a
//! per-session secret and are useless after the [`StreamingScanSession`] is
//! dropped. They are locators, never durable capabilities.

use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::directory_io::{
    BindDirectoryError, BindFileError, BoundDirectory, BoundFile, BoundRootAnchor, EntryKind,
};
use crate::file_io::{snapshot_path, FileSnapshot, StableOpenError};
use crate::model::{
    FileId, FileTimestamp, MediaKind, PathRef, ProgressStage, ScanIssue, ScanIssueCode,
    ScanProgress, ScanStats,
};
use crate::{ScanControl, ScanError, Scanner};

/// Maximum number of caller-provided tickets or pairs accepted by one stage
/// call. This is a hard safety limit, independent of configured event batches.
pub const STREAM_INPUT_BATCH_HARD_MAX: usize = 128;

/// Absolute maximum event count in one synchronous sink callback.
pub const STREAM_EVENT_BATCH_HARD_MAX: usize = 128;
/// Absolute maximum estimated payload bytes in one sink callback.
pub const STREAM_EVENT_BYTES_HARD_MAX: usize = 1024 * 1024;
/// Smallest accepted estimated-byte budget for an event batch.
pub const STREAM_EVENT_BYTES_MIN: usize = 16 * 1024;
/// Absolute maximum encoded size of one authenticated opaque ticket.
pub const STREAM_TICKET_BYTES_HARD_MAX: usize = 64 * 1024;
const STREAM_ROOTS_HARD_MAX: usize = 64;
const ISSUE_DETAIL_BYTES_MAX: usize = 4096;
const EXACT_BUFFER_BYTES_MAX: usize = 1024 * 1024;
const TICKET_MAGIC: &[u8; 4] = b"GYTK";
const TICKET_VERSION: u8 = 1;
const TICKET_MAC_BYTES: usize = 32;

/// Count and byte limits for batches handed to a [`StreamingScanSink`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamLimits {
    pub max_events_per_batch: usize,
    pub max_bytes_per_batch: usize,
}

impl Default for StreamLimits {
    fn default() -> Self {
        Self {
            max_events_per_batch: 64,
            max_bytes_per_batch: 256 * 1024,
        }
    }
}

impl StreamLimits {
    fn validate(self) -> Result<Self, ScanError> {
        if !(1..=STREAM_EVENT_BATCH_HARD_MAX).contains(&self.max_events_per_batch) {
            return Err(ScanError::InvalidOption(format!(
                "max_events_per_batch must be in 1..={STREAM_EVENT_BATCH_HARD_MAX}"
            )));
        }
        if !(STREAM_EVENT_BYTES_MIN..=STREAM_EVENT_BYTES_HARD_MAX)
            .contains(&self.max_bytes_per_batch)
        {
            return Err(ScanError::InvalidOption(format!(
                "max_bytes_per_batch must be in {STREAM_EVENT_BYTES_MIN}..={STREAM_EVENT_BYTES_HARD_MAX}"
            )));
        }
        Ok(self)
    }
}

/// Random identity of one live core scan session.
///
/// This is not a volume mount-session key and must never be used as one.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StreamSessionId([u8; 32]);

impl StreamSessionId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The strongest trust scope core can claim without a volume capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamTrustScope {
    /// Valid only while the live session and its root descriptors exist.
    CurrentCoreSessionOnly,
}

/// Failure while decoding or authenticating an opaque session ticket.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TicketDecodeError {
    Empty,
    TooLarge,
    Malformed,
    WrongKind,
    WrongSession,
    AuthenticationFailed,
    UnsupportedPathEncoding,
}

impl fmt::Display for TicketDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Empty => "ticket is empty",
            Self::TooLarge => "ticket exceeds the hard byte limit",
            Self::Malformed => "ticket has a malformed canonical payload",
            Self::WrongKind => "ticket has the wrong evidence kind",
            Self::WrongSession => "ticket belongs to another scan session",
            Self::AuthenticationFailed => "ticket authentication failed",
            Self::UnsupportedPathEncoding => "ticket path encoding is unsupported on this platform",
        };
        formatter.write_str(message)
    }
}

impl Error for TicketDecodeError {}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OpaqueTicket {
    bytes: Vec<u8>,
    sort_key: [u8; 32],
}

impl OpaqueTicket {
    fn from_untrusted_bytes(
        bytes: &[u8],
        expected_kind: TicketKind,
    ) -> Result<Self, TicketDecodeError> {
        if bytes.is_empty() {
            return Err(TicketDecodeError::Empty);
        }
        if bytes.len() > STREAM_TICKET_BYTES_HARD_MAX {
            return Err(TicketDecodeError::TooLarge);
        }
        if bytes.len() < 8 + 32 + 2 + 2 + 32 + TICKET_MAC_BYTES
            || &bytes[..4] != TICKET_MAGIC
            || bytes[4] != TICKET_VERSION
        {
            return Err(TicketDecodeError::Malformed);
        }
        if bytes[5] != expected_kind as u8 {
            return Err(TicketDecodeError::WrongKind);
        }
        Ok(Self {
            sort_key: ticket_sort_key(bytes),
            bytes: bytes.to_vec(),
        })
    }
}

/// Opaque, authenticated locator for one enumerated regular file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileObservationTicket(OpaqueTicket);

impl FileObservationTicket {
    /// Restores untrusted bytes for presentation to the same live session.
    /// Authentication occurs only when a session read method consumes it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TicketDecodeError> {
        OpaqueTicket::from_untrusted_bytes(bytes, TicketKind::File).map(Self)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0.bytes
    }

    pub fn sort_key(&self) -> &[u8; 32] {
        &self.0.sort_key
    }
}

/// Opaque, authenticated locator for one enumerated directory audit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryObservationTicket(OpaqueTicket);

impl DirectoryObservationTicket {
    /// Restores untrusted bytes for presentation to the same live session.
    /// Authentication occurs only when a session consumes it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TicketDecodeError> {
        OpaqueTicket::from_untrusted_bytes(bytes, TicketKind::Directory).map(Self)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0.bytes
    }

    pub fn sort_key(&self) -> &[u8; 32] {
        &self.0.sort_key
    }
}

/// Immutable file observation emitted during descriptor-anchored enumeration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileObservation {
    pub root_index: u16,
    /// Lossless locator under the selected root, produced from authenticated
    /// native components and suitable for a volume adapter to revalidate.
    pub root_relative_path: PathRef,
    /// Absolute diagnostic path only. Never strip a prefix from this field to
    /// recover an addressing key.
    pub path: PathRef,
    pub media_kind: MediaKind,
    pub size: u64,
    pub allocated_size: Option<u64>,
    /// Informational only. Filesystem reads may update atime, so this field is
    /// intentionally excluded from stable identity comparisons.
    pub observed_accessed: Option<FileTimestamp>,
    pub modified: Option<FileTimestamp>,
    pub created: Option<FileTimestamp>,
    pub change_time: Option<FileTimestamp>,
    pub file_id: Option<FileId>,
    pub generation: Option<u32>,
    pub mode: Option<u32>,
    pub hard_link_count: Option<u64>,
    pub source_signature: [u8; 32],
    pub ticket: FileObservationTicket,
}

/// Immutable directory observation used for final coverage revalidation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryObservation {
    pub root_index: u16,
    /// Lossless locator under the selected root; empty for the root itself.
    pub root_relative_path: PathRef,
    /// Absolute diagnostic path only; not a durable locator.
    pub path: PathRef,
    pub size: u64,
    pub allocated_size: Option<u64>,
    /// Informational only; not part of stable directory identity.
    pub observed_accessed: Option<FileTimestamp>,
    pub modified: Option<FileTimestamp>,
    pub created: Option<FileTimestamp>,
    pub change_time: Option<FileTimestamp>,
    pub file_id: Option<FileId>,
    pub generation: Option<u32>,
    pub mode: Option<u32>,
    pub hard_link_count: Option<u64>,
    pub source_signature: [u8; 32],
    pub ticket: DirectoryObservationTicket,
}

/// Kind of a root actually bound by the streaming session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamRootKind {
    Directory,
    /// Compatibility-only standalone file root. The persistent runtime must
    /// reject it until `guiying-volume` provides an equivalent pinned root-file
    /// binding; its directory-scoped capability is not interchangeable.
    RegularFile,
}

/// Explicit root descriptor evidence for runtime/volume binding.
///
/// On macOS, `device`, `inode`, `generation`, `mode`, and `change_time`
/// correspond to the fields in `guiying_volume::RootObjectIdentity`. A runtime
/// must compare them and the volume root/source binding before upgrading core
/// evidence beyond [`StreamTrustScope::CurrentCoreSessionOnly`]. Matching root
/// fields is necessary but not sufficient: `st_dev` alone cannot detect every
/// same-device descendant/bind mount.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamRootObservation {
    pub root_index: u16,
    pub path: PathRef,
    pub kind: StreamRootKind,
    pub size: u64,
    pub allocated_size: Option<u64>,
    /// Informational only and excluded from stable source identity.
    pub observed_accessed: Option<FileTimestamp>,
    pub file_id: Option<FileId>,
    pub generation: Option<u32>,
    pub mode: Option<u32>,
    pub hard_link_count: Option<u64>,
    pub created: Option<FileTimestamp>,
    pub modified: Option<FileTimestamp>,
    pub change_time: Option<FileTimestamp>,
    pub source_signature: [u8; 32],
}

/// Origin of a fresh fingerprint. Callers cannot construct proof instances.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreshReadOrigin {
    CurrentSessionSample,
    CurrentSessionFullHash,
}

/// Sealed evidence produced by an actual read through an authenticated ticket.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreshFingerprintEvidence {
    session_id: StreamSessionId,
    trust_scope: StreamTrustScope,
    path: PathRef,
    observation_ticket_id: [u8; 32],
    read_origin: FreshReadOrigin,
    algorithm: &'static str,
    algorithm_version: u32,
    parameters_hash: [u8; 32],
    digest: [u8; 32],
    expected_length: u64,
    bytes_read: u64,
    eof_verified: bool,
    before_source_signature: [u8; 32],
    after_source_signature: [u8; 32],
}

impl FreshFingerprintEvidence {
    pub fn session_id(&self) -> StreamSessionId {
        self.session_id
    }
    pub fn trust_scope(&self) -> StreamTrustScope {
        self.trust_scope
    }
    pub fn path(&self) -> &PathRef {
        &self.path
    }
    pub fn observation_ticket_id(&self) -> &[u8; 32] {
        &self.observation_ticket_id
    }
    pub fn read_origin(&self) -> FreshReadOrigin {
        self.read_origin
    }
    pub fn algorithm(&self) -> &'static str {
        self.algorithm
    }
    pub fn algorithm_version(&self) -> u32 {
        self.algorithm_version
    }
    pub fn parameters_hash(&self) -> &[u8; 32] {
        &self.parameters_hash
    }
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn expected_length(&self) -> u64 {
        self.expected_length
    }
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }
    pub fn eof_verified(&self) -> bool {
        self.eof_verified
    }
    pub fn before_source_signature(&self) -> &[u8; 32] {
        &self.before_source_signature
    }
    pub fn after_source_signature(&self) -> &[u8; 32] {
        &self.after_source_signature
    }
}

/// Caller-selected pair of authenticated observations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExactCandidatePair {
    left: FileObservationTicket,
    right: FileObservationTicket,
}

impl ExactCandidatePair {
    pub fn new(left: FileObservationTicket, right: FileObservationTicket) -> Self {
        Self { left, right }
    }
}

/// Sealed result of a byte comparison performed through two pinned locators.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExactComparisonEvidence {
    session_id: StreamSessionId,
    trust_scope: StreamTrustScope,
    left_path: PathRef,
    right_path: PathRef,
    left_observation_ticket_id: [u8; 32],
    right_observation_ticket_id: [u8; 32],
    left_expected_length: u64,
    right_expected_length: u64,
    bytes_compared: u64,
    identical: bool,
    eof_verified: bool,
    digest_algorithm: &'static str,
    digest_algorithm_version: u32,
    digest_parameters_hash: [u8; 32],
    left_digest: Option<[u8; 32]>,
    right_digest: Option<[u8; 32]>,
    left_before_source_signature: [u8; 32],
    left_after_source_signature: [u8; 32],
    right_before_source_signature: [u8; 32],
    right_after_source_signature: [u8; 32],
}

impl ExactComparisonEvidence {
    pub fn session_id(&self) -> StreamSessionId {
        self.session_id
    }
    pub fn trust_scope(&self) -> StreamTrustScope {
        self.trust_scope
    }
    pub fn left_path(&self) -> &PathRef {
        &self.left_path
    }
    pub fn right_path(&self) -> &PathRef {
        &self.right_path
    }
    pub fn left_observation_ticket_id(&self) -> &[u8; 32] {
        &self.left_observation_ticket_id
    }
    pub fn right_observation_ticket_id(&self) -> &[u8; 32] {
        &self.right_observation_ticket_id
    }
    pub fn left_expected_length(&self) -> u64 {
        self.left_expected_length
    }
    pub fn right_expected_length(&self) -> u64 {
        self.right_expected_length
    }
    pub fn bytes_compared(&self) -> u64 {
        self.bytes_compared
    }
    pub fn identical(&self) -> bool {
        self.identical
    }
    pub fn eof_verified(&self) -> bool {
        self.eof_verified
    }
    pub fn digest_algorithm(&self) -> &'static str {
        self.digest_algorithm
    }
    pub fn digest_algorithm_version(&self) -> u32 {
        self.digest_algorithm_version
    }
    pub fn digest_parameters_hash(&self) -> &[u8; 32] {
        &self.digest_parameters_hash
    }
    pub fn left_digest(&self) -> Option<&[u8; 32]> {
        self.left_digest.as_ref()
    }
    pub fn right_digest(&self) -> Option<&[u8; 32]> {
        self.right_digest.as_ref()
    }
    pub fn left_before_source_signature(&self) -> &[u8; 32] {
        &self.left_before_source_signature
    }
    pub fn left_after_source_signature(&self) -> &[u8; 32] {
        &self.left_after_source_signature
    }
    pub fn right_before_source_signature(&self) -> &[u8; 32] {
        &self.right_before_source_signature
    }
    pub fn right_after_source_signature(&self) -> &[u8; 32] {
        &self.right_after_source_signature
    }
}

/// Final local-walker directory-coverage seal.
///
/// This is current-core-session evidence only. It cannot be persisted as a v5
/// coverage seal unless the runtime has independently revalidated every
/// root-relative locator and fresh read with the active volume mount signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverageSeal {
    session_id: StreamSessionId,
    trust_scope: StreamTrustScope,
    directory_observations: u64,
    directory_manifest_digest: [u8; 32],
    seal_digest: [u8; 32],
}

impl CoverageSeal {
    pub fn session_id(&self) -> StreamSessionId {
        self.session_id
    }
    pub fn trust_scope(&self) -> StreamTrustScope {
        self.trust_scope
    }
    pub fn directory_observations(&self) -> u64 {
        self.directory_observations
    }
    pub fn directory_manifest_digest(&self) -> &[u8; 32] {
        &self.directory_manifest_digest
    }
    pub fn seal_digest(&self) -> &[u8; 32] {
        &self.seal_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamBatchStatus {
    Completed,
    Partial,
    Cancelled,
    Interrupted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamingEnumerationOutcome {
    pub status: StreamBatchStatus,
    pub stats: ScanStats,
    pub directory_observations: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageBatchOutcome {
    pub status: StreamBatchStatus,
    pub completed: u64,
    pub failed: u64,
}

/// Bounded events written synchronously to durable runtime storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StreamEvent {
    RootObservation(StreamRootObservation),
    FileObservation(FileObservation),
    DirectoryObservation(DirectoryObservation),
    Issue(ScanIssue),
    Progress(ScanProgress),
    FreshFingerprint(FreshFingerprintEvidence),
    ExactComparison(ExactComparisonEvidence),
    EnumerationFinished(StreamingEnumerationOutcome),
    CoverageVerified(CoverageSeal),
}

/// Synchronous event sink. Returning only after durable acceptance provides
/// backpressure; returning an error poisons the session fail closed.
pub trait StreamingScanSink {
    type Error;

    fn write_batch(&mut self, events: &[StreamEvent]) -> Result<(), Self::Error>;
}

/// Failure of a bounded streaming operation.
#[derive(Debug)]
pub enum StreamScanError<E> {
    Sink(E),
    InvalidState(&'static str),
    InputBatchTooLarge { supplied: usize, maximum: usize },
    Ticket(TicketDecodeError),
    EventTooLarge { estimated: usize, maximum: usize },
    DirectoryTicketOrder,
    CoverageIncomplete { expected: u64, supplied: u64 },
    CoverageSetMismatch,
}

impl<E: fmt::Display> fmt::Display for StreamScanError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sink(error) => write!(formatter, "stream sink rejected a batch: {error}"),
            Self::InvalidState(message) => write!(formatter, "invalid streaming session state: {message}"),
            Self::InputBatchTooLarge { supplied, maximum } => write!(
                formatter,
                "input batch contains {supplied} items; hard maximum is {maximum}"
            ),
            Self::Ticket(error) => write!(formatter, "invalid session ticket: {error}"),
            Self::EventTooLarge { estimated, maximum } => write!(
                formatter,
                "single stream event is estimated at {estimated} bytes; batch maximum is {maximum}"
            ),
            Self::DirectoryTicketOrder => formatter.write_str(
                "directory tickets must be replayed exactly once in strictly increasing sort-key order",
            ),
            Self::CoverageIncomplete { expected, supplied } => write!(
                formatter,
                "directory coverage is incomplete: expected {expected} tickets, received {supplied}"
            ),
            Self::CoverageSetMismatch => formatter.write_str(
                "directory coverage tickets do not match the enumerated ticket set",
            ),
        }
    }
}

impl<E> Error for StreamScanError<E>
where
    E: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sink(error) => Some(error),
            Self::Ticket(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionState {
    Ready,
    Enumerating,
    Enumerated,
    CoverageVerified,
    Cancelled,
    Interrupted,
    Poisoned,
}

#[derive(Clone, Debug)]
struct PendingRoot {
    path: PathBuf,
    is_directory: bool,
    snapshot: FileSnapshot,
}

#[derive(Clone)]
enum RootAccess {
    Directory {
        path: PathBuf,
        anchor: BoundRootAnchor,
    },
    File {
        path: PathBuf,
        binding: BoundFile,
        snapshot: Box<FileSnapshot>,
        ticket: FileObservationTicket,
    },
}

/// Live, descriptor-bound scan session used by the persistent runtime.
///
/// It never exposes mutation APIs. Evidence remains `CurrentCoreSessionOnly`;
/// a runtime must combine it with `guiying-volume` mount/session evidence before
/// accepting it as durable v5 fresh evidence.
pub struct StreamingScanSession {
    scanner: Scanner,
    limits: StreamLimits,
    session_id: StreamSessionId,
    ticket_key: [u8; 32],
    pending_roots: Vec<PendingRoot>,
    roots: Vec<Option<RootAccess>>,
    state: SessionState,
    expected_directory_tickets: u64,
    expected_directory_ticket_xor: [u8; 32],
    verified_directory_tickets: u64,
    verified_directory_failures: u64,
    verified_directory_ticket_xor: [u8; 32],
    verified_directory_manifest: blake3::Hasher,
    last_directory_sort_key: Option<[u8; 32]>,
    coverage_stable: bool,
    enumeration_partial: bool,
}

impl Scanner {
    /// Starts a bounded streaming session without constructing a `ScanReport`.
    /// Every root must be absolute; relative roots are rejected without
    /// consulting or resolving the process working directory.
    pub fn start_streaming<I, P>(
        &self,
        roots: I,
        limits: StreamLimits,
    ) -> Result<StreamingScanSession, ScanError>
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        let limits = limits.validate()?;
        let mut roots: Vec<PathBuf> = roots.into_iter().map(Into::into).collect();
        if roots.is_empty() {
            return Err(ScanError::NoRoots);
        }
        if let Some(path) = roots.iter().find(|path| !path.is_absolute()) {
            return Err(ScanError::RelativeRoot(path.clone()));
        }
        roots.sort();
        roots.dedup();
        if roots.len() > STREAM_ROOTS_HARD_MAX {
            return Err(ScanError::InvalidOption(format!(
                "streaming scans support at most {STREAM_ROOTS_HARD_MAX} roots"
            )));
        }

        let mut pending_roots = Vec::with_capacity(roots.len());
        for path in roots {
            let (metadata, snapshot) =
                snapshot_path(&path).map_err(|source| ScanError::RootMetadata {
                    path: path.clone(),
                    source,
                })?;
            if metadata.file_type().is_symlink() {
                return Err(ScanError::RootIsSymlink(path));
            }
            if !metadata.file_type().is_file() && !metadata.file_type().is_dir() {
                return Err(ScanError::UnsupportedRoot(path));
            }
            if metadata.file_type().is_dir() {
                if let Some(reason) = self.options().directory_exclusion(&path) {
                    return Err(ScanError::ExcludedRoot { path, reason });
                }
            }
            pending_roots.push(PendingRoot {
                path,
                is_directory: metadata.file_type().is_dir(),
                snapshot,
            });
        }

        let mut entropy = [0_u8; 64];
        getrandom::fill(&mut entropy)
            .map_err(|error| ScanError::SessionEntropy(error.to_string()))?;
        let mut id_hasher = blake3::Hasher::new();
        id_hasher.update(b"guiying.core-stream-session.v1\0");
        id_hasher.update(&entropy[..32]);
        let session_id = StreamSessionId(*id_hasher.finalize().as_bytes());
        let mut ticket_key = [0_u8; 32];
        ticket_key.copy_from_slice(&entropy[32..]);

        Ok(StreamingScanSession {
            scanner: self.clone(),
            limits,
            session_id,
            ticket_key,
            pending_roots,
            roots: Vec::new(),
            state: SessionState::Ready,
            expected_directory_tickets: 0,
            expected_directory_ticket_xor: [0_u8; 32],
            verified_directory_tickets: 0,
            verified_directory_failures: 0,
            verified_directory_ticket_xor: [0_u8; 32],
            verified_directory_manifest: directory_manifest_hasher(session_id),
            last_directory_sort_key: None,
            coverage_stable: true,
            enumeration_partial: false,
        })
    }
}

impl StreamingScanSession {
    pub fn session_id(&self) -> StreamSessionId {
        self.session_id
    }

    pub fn trust_scope(&self) -> StreamTrustScope {
        StreamTrustScope::CurrentCoreSessionOnly
    }

    /// Enumerates with O(configured depth + bounded batch) core memory.
    pub fn enumerate<S: StreamingScanSink>(
        &mut self,
        sink: &mut S,
        control: &dyn ScanControl,
    ) -> Result<StreamingEnumerationOutcome, StreamScanError<S::Error>> {
        if self.state != SessionState::Ready {
            return Err(StreamScanError::InvalidState(
                "enumeration is allowed exactly once",
            ));
        }
        self.state = SessionState::Enumerating;
        let result = self.enumerate_inner(sink, control);
        match result {
            Ok(outcome) => {
                self.state = match outcome.status {
                    StreamBatchStatus::Completed | StreamBatchStatus::Partial => {
                        SessionState::Enumerated
                    }
                    StreamBatchStatus::Cancelled => SessionState::Cancelled,
                    StreamBatchStatus::Interrupted => SessionState::Interrupted,
                };
                Ok(outcome)
            }
            Err(error) => {
                self.state = SessionState::Poisoned;
                Err(error)
            }
        }
    }

    fn enumerate_inner<S: StreamingScanSink>(
        &mut self,
        sink: &mut S,
        control: &dyn ScanControl,
    ) -> Result<StreamingEnumerationOutcome, StreamScanError<S::Error>> {
        let mut events = EventBuffer::new(sink, self.limits);
        let mut stats = ScanStats::default();
        let mut partial = false;
        let mut root_accesses: Vec<Option<RootAccess>> =
            (0..self.pending_roots.len()).map(|_| None).collect();
        let pending_roots = self.pending_roots.clone();
        let mut accepted_root_directory_ids = Vec::<FileId>::new();

        for (root_index, root) in pending_roots.iter().enumerate() {
            if control.is_cancelled() {
                let outcome = enumeration_outcome(
                    StreamBatchStatus::Cancelled,
                    stats,
                    self.expected_directory_tickets,
                );
                events.push(StreamEvent::EnumerationFinished(outcome.clone()))?;
                events.finish()?;
                return Ok(outcome);
            }
            if root.is_directory {
                let bound_root = match BoundDirectory::bind_root(root.path.clone(), &root.snapshot)
                {
                    Ok(bound) => bound,
                    Err(error) => {
                        emit_issue(
                            &mut events,
                            &mut stats,
                            &mut partial,
                            directory_bind_issue(root.path.clone(), error, true),
                        )?;
                        let outcome = enumeration_outcome(
                            StreamBatchStatus::Interrupted,
                            stats,
                            self.expected_directory_tickets,
                        );
                        events.push(StreamEvent::EnumerationFinished(outcome.clone()))?;
                        events.finish()?;
                        return Ok(outcome);
                    }
                };
                let root_device = root.snapshot.device();
                let anchor = bound_root.root_anchor();
                root_accesses[root_index] = Some(RootAccess::Directory {
                    path: root.path.clone(),
                    anchor,
                });
                events.push(StreamEvent::RootObservation(make_root_observation(
                    self.session_id,
                    root_index,
                    root.path.clone(),
                    StreamRootKind::Directory,
                    bound_root.snapshot(),
                )))?;
                let Some(root_identity) = bound_root.identity() else {
                    emit_issue(
                        &mut events,
                        &mut stats,
                        &mut partial,
                        make_issue(
                            ScanIssueCode::MetadataUnreadable,
                            root.path.clone(),
                            "opened root directory has no stable device/inode identity".to_owned(),
                        ),
                    )?;
                    continue;
                };
                if accepted_root_directory_ids.contains(&root_identity) {
                    stats.directory_identity_revisits_skipped =
                        stats.directory_identity_revisits_skipped.saturating_add(1);
                    emit_issue(
                        &mut events,
                        &mut stats,
                        &mut partial,
                        make_issue(
                            ScanIssueCode::DirectoryIdentityAlreadyVisited,
                            root.path.clone(),
                            format!(
                                "root directory identity ({}, {}) was already selected",
                                root_identity.device, root_identity.inode
                            ),
                        ),
                    )?;
                    continue;
                }
                accepted_root_directory_ids.push(root_identity);
                self.emit_directory_observation(root_index, &bound_root, &mut events)?;
                let mut stack = vec![StreamDirectoryFrame {
                    root_index,
                    root_device,
                    depth: 0,
                    directory: bound_root,
                }];

                while !stack.is_empty() {
                    if control.is_cancelled() {
                        let outcome = enumeration_outcome(
                            StreamBatchStatus::Cancelled,
                            stats,
                            self.expected_directory_tickets,
                        );
                        events.push(StreamEvent::EnumerationFinished(outcome.clone()))?;
                        events.finish()?;
                        return Ok(outcome);
                    }

                    let next = {
                        let frame = stack.last_mut().expect("stack checked non-empty");
                        frame.directory.next_name()
                    };
                    let name = match next {
                        Ok(Some(name)) => name,
                        Ok(None) => {
                            stack.pop();
                            continue;
                        }
                        Err(error) => {
                            let path = stack
                                .last()
                                .expect("stack checked non-empty")
                                .directory
                                .path()
                                .to_path_buf();
                            emit_issue(
                                &mut events,
                                &mut stats,
                                &mut partial,
                                make_issue(
                                    ScanIssueCode::DirectoryUnreadable,
                                    path,
                                    error.to_string(),
                                ),
                            )?;
                            stack.pop();
                            continue;
                        }
                    };

                    let (path, kind, child_depth, frame_root_index, frame_root_device) = {
                        let frame = stack.last().expect("stack checked non-empty");
                        let path = frame.directory.path().join(&name);
                        let kind = frame.directory.entry_kind(&name);
                        (
                            path,
                            kind,
                            frame.depth.saturating_add(1),
                            frame.root_index,
                            frame.root_device,
                        )
                    };
                    stats.entries_seen = stats.entries_seen.saturating_add(1);
                    events.push(StreamEvent::Progress(ScanProgress {
                        stage: ProgressStage::Enumerating,
                        completed: stats.entries_seen,
                        total: None,
                        current_path: Some(PathRef::from_path(&path)),
                    }))?;
                    if control.is_cancelled() {
                        let outcome = enumeration_outcome(
                            StreamBatchStatus::Cancelled,
                            stats,
                            self.expected_directory_tickets,
                        );
                        events.push(StreamEvent::EnumerationFinished(outcome.clone()))?;
                        events.finish()?;
                        return Ok(outcome);
                    }
                    let kind = match kind {
                        Ok(kind) => kind,
                        Err(error) => {
                            emit_issue(
                                &mut events,
                                &mut stats,
                                &mut partial,
                                make_issue(
                                    ScanIssueCode::MetadataUnreadable,
                                    path,
                                    error.to_string(),
                                ),
                            )?;
                            continue;
                        }
                    };

                    match kind {
                        EntryKind::Symlink => {
                            stats.symlinks_skipped = stats.symlinks_skipped.saturating_add(1);
                            emit_issue(
                                &mut events,
                                &mut stats,
                                &mut partial,
                                make_issue(
                                    ScanIssueCode::SymlinkSkipped,
                                    path,
                                    "symbolic links are never followed".to_owned(),
                                ),
                            )?;
                        }
                        EntryKind::Directory => {
                            if let Some(reason) = self.scanner.options().directory_exclusion(&path)
                            {
                                stats.excluded_directories_skipped =
                                    stats.excluded_directories_skipped.saturating_add(1);
                                emit_issue(
                                    &mut events,
                                    &mut stats,
                                    &mut partial,
                                    make_issue(ScanIssueCode::DirectoryExcluded, path, reason),
                                )?;
                            } else if child_depth > self.scanner.options().max_directory_depth {
                                stats.directory_depth_limit_skipped =
                                    stats.directory_depth_limit_skipped.saturating_add(1);
                                emit_issue(
                                    &mut events,
                                    &mut stats,
                                    &mut partial,
                                    make_issue(
                                        ScanIssueCode::DirectoryDepthLimitReached,
                                        path,
                                        format!(
                                            "directory depth {child_depth} exceeds the configured safe limit {}",
                                            self.scanner.options().max_directory_depth
                                        ),
                                    ),
                                )?;
                            } else {
                                let child = {
                                    let frame = stack.last().expect("stack checked non-empty");
                                    frame.directory.bind_child(&name, path.clone())
                                };
                                match child {
                                    Ok(child) => {
                                        if self.scanner.options().stay_on_filesystem
                                            && frame_root_device.is_some()
                                            && child.device() != frame_root_device
                                        {
                                            stats.cross_filesystem_directories_skipped = stats
                                                .cross_filesystem_directories_skipped
                                                .saturating_add(1);
                                            emit_issue(
                                                &mut events,
                                                &mut stats,
                                                &mut partial,
                                                make_issue(
                                                    ScanIssueCode::CrossFilesystemSkipped,
                                                    path,
                                                    "nested filesystem is outside the scan root volume"
                                                        .to_owned(),
                                                ),
                                            )?;
                                        } else if child.identity().is_some_and(|identity| {
                                            stack.iter().any(|ancestor| {
                                                ancestor.directory.identity() == Some(identity)
                                            })
                                        }) {
                                            stats.directory_identity_revisits_skipped = stats
                                                .directory_identity_revisits_skipped
                                                .saturating_add(1);
                                            emit_issue(
                                                &mut events,
                                                &mut stats,
                                                &mut partial,
                                                make_issue(
                                                    ScanIssueCode::DirectoryIdentityAlreadyVisited,
                                                    path,
                                                    "directory identity matches an active ancestor; possible mount loop"
                                                        .to_owned(),
                                                ),
                                            )?;
                                        } else if child.identity().is_none() {
                                            emit_issue(
                                                &mut events,
                                                &mut stats,
                                                &mut partial,
                                                make_issue(
                                                    ScanIssueCode::MetadataUnreadable,
                                                    path,
                                                    "opened directory has no stable device/inode identity"
                                                        .to_owned(),
                                                ),
                                            )?;
                                        } else {
                                            self.emit_directory_observation(
                                                frame_root_index,
                                                &child,
                                                &mut events,
                                            )?;
                                            stack.push(StreamDirectoryFrame {
                                                root_index: frame_root_index,
                                                root_device: frame_root_device,
                                                depth: child_depth,
                                                directory: child,
                                            });
                                        }
                                    }
                                    Err(error) => emit_issue(
                                        &mut events,
                                        &mut stats,
                                        &mut partial,
                                        directory_bind_issue(path, error, false),
                                    )?,
                                }
                            }
                        }
                        EntryKind::RegularFile => {
                            if let Some(media_kind) = self.scanner.options().media_kind(&path) {
                                let info = {
                                    let frame = stack.last().expect("stack checked non-empty");
                                    frame.directory.bind_regular_file(&name, path.clone())
                                };
                                match info {
                                    Ok(info) => {
                                        if self.scanner.options().stay_on_filesystem
                                            && frame_root_device.is_some()
                                            && info.snapshot.device() != frame_root_device
                                        {
                                            stats.cross_filesystem_files_skipped = stats
                                                .cross_filesystem_files_skipped
                                                .saturating_add(1);
                                            emit_issue(
                                                &mut events,
                                                &mut stats,
                                                &mut partial,
                                                make_issue(
                                                    ScanIssueCode::CrossFilesystemSkipped,
                                                    path,
                                                    "file is outside the scan root volume"
                                                        .to_owned(),
                                                ),
                                            )?;
                                        } else {
                                            let mut components = stack
                                                .last()
                                                .expect("stack checked non-empty")
                                                .directory
                                                .relative_components()
                                                .to_vec();
                                            components.push(name.clone());
                                            let observation = self.make_file_observation(
                                                frame_root_index,
                                                &components,
                                                path,
                                                media_kind,
                                                &info.snapshot,
                                            )?;
                                            stats.media_files = stats.media_files.saturating_add(1);
                                            events
                                                .push(StreamEvent::FileObservation(observation))?;
                                        }
                                    }
                                    Err(error) => emit_issue(
                                        &mut events,
                                        &mut stats,
                                        &mut partial,
                                        file_bind_issue(path, error),
                                    )?,
                                }
                            } else {
                                stats.non_media_files_skipped =
                                    stats.non_media_files_skipped.saturating_add(1);
                            }
                        }
                        EntryKind::Other => {
                            stats.special_files_skipped =
                                stats.special_files_skipped.saturating_add(1);
                            emit_issue(
                                &mut events,
                                &mut stats,
                                &mut partial,
                                make_issue(
                                    ScanIssueCode::UnsupportedFileType,
                                    path,
                                    "only regular files are scanned".to_owned(),
                                ),
                            )?;
                        }
                    }
                }
            } else {
                let Some(media_kind) = self.scanner.options().media_kind(&root.path) else {
                    stats.non_media_files_skipped = stats.non_media_files_skipped.saturating_add(1);
                    continue;
                };
                let binding = match BoundFile::bind_root_file(root.path.clone(), &root.snapshot) {
                    Ok(binding) => binding,
                    Err(error) => {
                        emit_issue(
                            &mut events,
                            &mut stats,
                            &mut partial,
                            stable_open_issue(root.path.clone(), error),
                        )?;
                        let outcome = enumeration_outcome(
                            StreamBatchStatus::Interrupted,
                            stats,
                            self.expected_directory_tickets,
                        );
                        events.push(StreamEvent::EnumerationFinished(outcome.clone()))?;
                        events.finish()?;
                        return Ok(outcome);
                    }
                };
                stats.entries_seen = stats.entries_seen.saturating_add(1);
                stats.media_files = stats.media_files.saturating_add(1);
                let observation = self.make_file_observation(
                    root_index,
                    &[],
                    root.path.clone(),
                    media_kind,
                    &root.snapshot,
                )?;
                let ticket = observation.ticket.clone();
                events.push(StreamEvent::RootObservation(make_root_observation(
                    self.session_id,
                    root_index,
                    root.path.clone(),
                    StreamRootKind::RegularFile,
                    &root.snapshot,
                )))?;
                events.push(StreamEvent::FileObservation(observation))?;
                root_accesses[root_index] = Some(RootAccess::File {
                    path: root.path.clone(),
                    binding,
                    snapshot: Box::new(root.snapshot.clone()),
                    ticket,
                });
            }
        }

        self.roots = root_accesses;
        self.enumeration_partial = partial;
        let outcome = enumeration_outcome(
            if partial {
                StreamBatchStatus::Partial
            } else {
                StreamBatchStatus::Completed
            },
            stats,
            self.expected_directory_tickets,
        );
        events.push(StreamEvent::EnumerationFinished(outcome.clone()))?;
        events.finish()?;
        Ok(outcome)
    }

    fn emit_directory_observation<S: StreamingScanSink>(
        &mut self,
        root_index: usize,
        directory: &BoundDirectory,
        events: &mut EventBuffer<'_, S>,
    ) -> Result<(), StreamScanError<S::Error>> {
        let root_relative_path = relative_path_ref(directory.relative_components());
        let signature = observation_source_signature(
            self.session_id,
            root_index,
            &root_relative_path,
            directory.snapshot(),
            SnapshotKind::Directory,
        );
        let ticket =
            self.make_directory_ticket(root_index, directory.relative_components(), signature)?;
        self.expected_directory_tickets = self.expected_directory_tickets.saturating_add(1);
        xor_digest(&mut self.expected_directory_ticket_xor, ticket.sort_key());
        events.push(StreamEvent::DirectoryObservation(DirectoryObservation {
            root_index: bounded_root_index(root_index),
            root_relative_path,
            path: PathRef::from_path(directory.path()),
            size: directory.snapshot().len,
            allocated_size: directory.snapshot().allocated_size,
            observed_accessed: directory.snapshot().accessed_timestamp(),
            modified: directory.snapshot().modified_timestamp(),
            created: directory.snapshot().created_timestamp(),
            change_time: directory.snapshot().change_timestamp(),
            file_id: directory.identity(),
            generation: directory.snapshot().generation(),
            mode: directory.snapshot().mode(),
            hard_link_count: directory.snapshot().hard_link_count,
            source_signature: signature,
            ticket,
        }))
    }

    fn make_file_observation<E>(
        &self,
        root_index: usize,
        relative_components: &[OsString],
        path: PathBuf,
        media_kind: MediaKind,
        snapshot: &FileSnapshot,
    ) -> Result<FileObservation, StreamScanError<E>> {
        let root_relative_path = relative_path_ref(relative_components);
        let signature = observation_source_signature(
            self.session_id,
            root_index,
            &root_relative_path,
            snapshot,
            SnapshotKind::File,
        );
        let ticket = self.make_file_ticket(root_index, relative_components, signature)?;
        Ok(FileObservation {
            root_index: bounded_root_index(root_index),
            root_relative_path,
            path: PathRef::from_path(&path),
            media_kind,
            size: snapshot.len,
            allocated_size: snapshot.allocated_size,
            observed_accessed: snapshot.accessed_timestamp(),
            modified: snapshot.modified_timestamp(),
            created: snapshot.created_timestamp(),
            change_time: snapshot.change_timestamp(),
            file_id: snapshot.file_id,
            generation: snapshot.generation(),
            mode: snapshot.mode(),
            hard_link_count: snapshot.hard_link_count,
            source_signature: signature,
            ticket,
        })
    }

    fn make_file_ticket<E>(
        &self,
        root_index: usize,
        components: &[OsString],
        signature: [u8; 32],
    ) -> Result<FileObservationTicket, StreamScanError<E>> {
        self.make_ticket(TicketKind::File, root_index, components, signature)
            .map(FileObservationTicket)
    }

    fn make_directory_ticket<E>(
        &self,
        root_index: usize,
        components: &[OsString],
        signature: [u8; 32],
    ) -> Result<DirectoryObservationTicket, StreamScanError<E>> {
        self.make_ticket(TicketKind::Directory, root_index, components, signature)
            .map(DirectoryObservationTicket)
    }

    fn make_ticket<E>(
        &self,
        kind: TicketKind,
        root_index: usize,
        components: &[OsString],
        signature: [u8; 32],
    ) -> Result<OpaqueTicket, StreamScanError<E>> {
        let root_index = u16::try_from(root_index)
            .map_err(|_| StreamScanError::Ticket(TicketDecodeError::Malformed))?;
        let component_count = u16::try_from(components.len())
            .map_err(|_| StreamScanError::Ticket(TicketDecodeError::TooLarge))?;
        let mut payload = Vec::with_capacity(128);
        payload.extend_from_slice(TICKET_MAGIC);
        payload.push(TICKET_VERSION);
        payload.push(kind as u8);
        payload.push(native_path_encoding_tag());
        payload.push(0);
        payload.extend_from_slice(self.session_id.as_bytes());
        payload.extend_from_slice(&root_index.to_le_bytes());
        payload.extend_from_slice(&component_count.to_le_bytes());
        for component in components {
            let bytes = encode_component(component)?;
            let len = u32::try_from(bytes.len())
                .map_err(|_| StreamScanError::Ticket(TicketDecodeError::TooLarge))?;
            payload.extend_from_slice(&len.to_le_bytes());
            payload.extend_from_slice(&bytes);
        }
        payload.extend_from_slice(&signature);
        if payload.len().saturating_add(TICKET_MAC_BYTES) > STREAM_TICKET_BYTES_HARD_MAX {
            return Err(StreamScanError::Ticket(TicketDecodeError::TooLarge));
        }
        let mac = blake3::keyed_hash(&self.ticket_key, &payload);
        payload.extend_from_slice(mac.as_bytes());
        Ok(OpaqueTicket {
            sort_key: ticket_sort_key(&payload),
            bytes: payload,
        })
    }

    /// Produces fresh sampled fingerprints for at most 128 authenticated files.
    pub fn sample_batch<S: StreamingScanSink>(
        &mut self,
        tickets: &[FileObservationTicket],
        sink: &mut S,
        control: &dyn ScanControl,
    ) -> Result<StageBatchOutcome, StreamScanError<S::Error>> {
        self.fingerprint_batch(
            tickets,
            sink,
            control,
            FreshReadOrigin::CurrentSessionSample,
        )
    }

    /// Produces fresh full-content BLAKE3 evidence with verified EOF.
    pub fn full_hash_batch<S: StreamingScanSink>(
        &mut self,
        tickets: &[FileObservationTicket],
        sink: &mut S,
        control: &dyn ScanControl,
    ) -> Result<StageBatchOutcome, StreamScanError<S::Error>> {
        self.fingerprint_batch(
            tickets,
            sink,
            control,
            FreshReadOrigin::CurrentSessionFullHash,
        )
    }

    fn fingerprint_batch<S: StreamingScanSink>(
        &mut self,
        tickets: &[FileObservationTicket],
        sink: &mut S,
        control: &dyn ScanControl,
        origin: FreshReadOrigin,
    ) -> Result<StageBatchOutcome, StreamScanError<S::Error>> {
        self.require_readable_state()?;
        validate_input_len(tickets.len())?;
        let result = self.fingerprint_batch_inner(tickets, sink, control, origin);
        if result.is_err() {
            self.state = SessionState::Poisoned;
        } else if result
            .as_ref()
            .is_ok_and(|outcome| outcome.status == StreamBatchStatus::Cancelled)
        {
            self.state = SessionState::Cancelled;
        }
        result
    }

    fn fingerprint_batch_inner<S: StreamingScanSink>(
        &self,
        tickets: &[FileObservationTicket],
        sink: &mut S,
        control: &dyn ScanControl,
        origin: FreshReadOrigin,
    ) -> Result<StageBatchOutcome, StreamScanError<S::Error>> {
        let mut events = EventBuffer::new(sink, self.limits);
        let mut completed = 0_u64;
        let mut failed = 0_u64;
        for ticket in tickets {
            if control.is_cancelled() {
                events.finish()?;
                return Ok(StageBatchOutcome {
                    status: StreamBatchStatus::Cancelled,
                    completed,
                    failed,
                });
            }
            let opened = match self.open_file_ticket(ticket) {
                Ok(opened) => opened,
                Err(TicketReadError::Ticket(error)) => return Err(StreamScanError::Ticket(error)),
                Err(error) => {
                    failed = failed.saturating_add(1);
                    events.push(StreamEvent::Issue(error.into_issue()))?;
                    continue;
                }
            };
            events.push(StreamEvent::Progress(ScanProgress {
                stage: match origin {
                    FreshReadOrigin::CurrentSessionSample => ProgressStage::Sampling,
                    FreshReadOrigin::CurrentSessionFullHash => ProgressStage::FullHashing,
                },
                completed,
                total: Some(tickets.len() as u64),
                current_path: Some(PathRef::from_path(&opened.path)),
            }))?;
            let read = match origin {
                FreshReadOrigin::CurrentSessionSample => read_sample_fresh(
                    &opened,
                    self.scanner.options().sample_bytes as usize,
                    control,
                ),
                FreshReadOrigin::CurrentSessionFullHash => read_full_fresh(
                    &opened,
                    self.scanner.options().read_buffer_bytes as usize,
                    control,
                ),
            };
            match read {
                Ok(evidence) => {
                    completed = completed.saturating_add(1);
                    events.push(StreamEvent::FreshFingerprint(evidence.with_session(
                        self.session_id,
                        ticket.0.sort_key,
                        origin,
                    )))?;
                }
                Err(FreshReadError::Cancelled) => {
                    events.finish()?;
                    return Ok(StageBatchOutcome {
                        status: StreamBatchStatus::Cancelled,
                        completed,
                        failed,
                    });
                }
                Err(error) => {
                    failed = failed.saturating_add(1);
                    events.push(StreamEvent::Issue(error.into_issue(opened.path)))?;
                }
            }
        }
        events.finish()?;
        Ok(StageBatchOutcome {
            status: StreamBatchStatus::Completed,
            completed,
            failed,
        })
    }

    /// Compares at most 128 caller-selected pairs through authenticated roots.
    pub fn exact_compare_batch<S: StreamingScanSink>(
        &mut self,
        pairs: &[ExactCandidatePair],
        sink: &mut S,
        control: &dyn ScanControl,
    ) -> Result<StageBatchOutcome, StreamScanError<S::Error>> {
        self.require_readable_state()?;
        validate_input_len(pairs.len())?;
        let result = self.exact_compare_batch_inner(pairs, sink, control);
        if result.is_err() {
            self.state = SessionState::Poisoned;
        } else if result
            .as_ref()
            .is_ok_and(|outcome| outcome.status == StreamBatchStatus::Cancelled)
        {
            self.state = SessionState::Cancelled;
        }
        result
    }

    fn exact_compare_batch_inner<S: StreamingScanSink>(
        &self,
        pairs: &[ExactCandidatePair],
        sink: &mut S,
        control: &dyn ScanControl,
    ) -> Result<StageBatchOutcome, StreamScanError<S::Error>> {
        let mut events = EventBuffer::new(sink, self.limits);
        let mut completed = 0_u64;
        let mut failed = 0_u64;
        for pair in pairs {
            if control.is_cancelled() {
                events.finish()?;
                return Ok(StageBatchOutcome {
                    status: StreamBatchStatus::Cancelled,
                    completed,
                    failed,
                });
            }
            if pair.left.0.sort_key == pair.right.0.sort_key {
                return Err(StreamScanError::Ticket(TicketDecodeError::Malformed));
            }
            let left = match self.open_file_ticket(&pair.left) {
                Ok(opened) => opened,
                Err(TicketReadError::Ticket(error)) => return Err(StreamScanError::Ticket(error)),
                Err(error) => {
                    failed = failed.saturating_add(1);
                    events.push(StreamEvent::Issue(error.into_issue()))?;
                    continue;
                }
            };
            let right = match self.open_file_ticket(&pair.right) {
                Ok(opened) => opened,
                Err(TicketReadError::Ticket(error)) => return Err(StreamScanError::Ticket(error)),
                Err(error) => {
                    failed = failed.saturating_add(1);
                    events.push(StreamEvent::Issue(error.into_issue()))?;
                    continue;
                }
            };
            events.push(StreamEvent::Progress(ScanProgress {
                stage: ProgressStage::ExactComparing,
                completed,
                total: Some(pairs.len() as u64),
                current_path: Some(PathRef::from_path(&right.path)),
            }))?;
            match compare_opened_fresh(
                &left,
                &right,
                self.scanner.options().read_buffer_bytes as usize,
                control,
            ) {
                Ok(evidence) => {
                    completed = completed.saturating_add(1);
                    events.push(StreamEvent::ExactComparison(evidence.with_session(
                        self.session_id,
                        pair.left.0.sort_key,
                        pair.right.0.sort_key,
                    )))?;
                }
                Err(ExactReadError::Cancelled) => {
                    events.finish()?;
                    return Ok(StageBatchOutcome {
                        status: StreamBatchStatus::Cancelled,
                        completed,
                        failed,
                    });
                }
                Err(error) => {
                    failed = failed.saturating_add(1);
                    events.push(StreamEvent::Issue(error.into_issue()))?;
                }
            }
        }
        events.finish()?;
        Ok(StageBatchOutcome {
            status: StreamBatchStatus::Completed,
            completed,
            failed,
        })
    }

    /// Revalidates a sorted, bounded page of directory tickets. The global
    /// order must be strictly increasing across calls, preventing duplicates.
    pub fn revalidate_directory_batch<S: StreamingScanSink>(
        &mut self,
        tickets: &[DirectoryObservationTicket],
        sink: &mut S,
        control: &dyn ScanControl,
    ) -> Result<StageBatchOutcome, StreamScanError<S::Error>> {
        self.require_readable_state()?;
        validate_input_len(tickets.len())?;
        let result = self.revalidate_directory_batch_inner(tickets, sink, control);
        if result.is_err() {
            self.state = SessionState::Poisoned;
        } else if result
            .as_ref()
            .is_ok_and(|outcome| outcome.status == StreamBatchStatus::Cancelled)
        {
            self.state = SessionState::Cancelled;
        }
        result
    }

    fn revalidate_directory_batch_inner<S: StreamingScanSink>(
        &mut self,
        tickets: &[DirectoryObservationTicket],
        sink: &mut S,
        control: &dyn ScanControl,
    ) -> Result<StageBatchOutcome, StreamScanError<S::Error>> {
        let mut events = EventBuffer::new(sink, self.limits);
        let mut completed = 0_u64;
        let mut failed = 0_u64;
        for ticket in tickets {
            if control.is_cancelled() {
                events.finish()?;
                return Ok(StageBatchOutcome {
                    status: StreamBatchStatus::Cancelled,
                    completed,
                    failed,
                });
            }
            if self
                .last_directory_sort_key
                .is_some_and(|previous| previous >= ticket.0.sort_key)
            {
                return Err(StreamScanError::DirectoryTicketOrder);
            }
            let claims = self
                .validate_ticket(&ticket.0, TicketKind::Directory)
                .map_err(StreamScanError::Ticket)?;
            let root = self
                .roots
                .get(claims.root_index)
                .and_then(Option::as_ref)
                .ok_or(StreamScanError::Ticket(TicketDecodeError::Malformed))?;
            let (root_path, anchor) = match root {
                RootAccess::Directory { path, anchor } => (path, anchor),
                RootAccess::File { .. } => {
                    return Err(StreamScanError::Ticket(TicketDecodeError::WrongKind))
                }
            };
            let path = join_components(root_path, &claims.components);
            let root_relative_path = relative_path_ref(&claims.components);
            let stable = match anchor.directory_snapshot(&claims.components) {
                Ok(snapshot) => {
                    observation_source_signature(
                        self.session_id,
                        claims.root_index,
                        &root_relative_path,
                        &snapshot,
                        SnapshotKind::Directory,
                    ) == claims.source_signature
                }
                Err(_) => false,
            };
            if stable {
                completed = completed.saturating_add(1);
            } else {
                failed = failed.saturating_add(1);
                self.verified_directory_failures = self
                    .verified_directory_failures
                    .checked_add(1)
                    .ok_or(StreamScanError::InvalidState(
                        "directory coverage failure count overflowed",
                    ))?;
                self.coverage_stable = false;
                events.push(StreamEvent::Issue(make_issue(
                    ScanIssueCode::DirectoryChangedDuringScan,
                    path,
                    "enumerated directory could not be revalidated through its root descriptor"
                        .to_owned(),
                )))?;
            }
            self.last_directory_sort_key = Some(ticket.0.sort_key);
            xor_digest(&mut self.verified_directory_ticket_xor, ticket.sort_key());
            self.verified_directory_manifest.update(ticket.sort_key());
            self.verified_directory_tickets = self.verified_directory_tickets.saturating_add(1);
            if self.verified_directory_tickets > self.expected_directory_tickets {
                return Err(StreamScanError::DirectoryTicketOrder);
            }
        }
        events.finish()?;
        Ok(StageBatchOutcome {
            status: StreamBatchStatus::Completed,
            completed,
            failed,
        })
    }

    /// Finalizes coverage only after every unique directory ticket is replayed.
    pub fn finalize_coverage<S: StreamingScanSink>(
        &mut self,
        sink: &mut S,
        control: &dyn ScanControl,
    ) -> Result<StageBatchOutcome, StreamScanError<S::Error>> {
        self.require_readable_state()?;
        if self.verified_directory_tickets != self.expected_directory_tickets {
            return Err(StreamScanError::CoverageIncomplete {
                expected: self.expected_directory_tickets,
                supplied: self.verified_directory_tickets,
            });
        }
        if self.verified_directory_ticket_xor != self.expected_directory_ticket_xor {
            return Err(StreamScanError::CoverageSetMismatch);
        }
        let result = self.finalize_coverage_inner(sink, control);
        match &result {
            Ok(outcome)
                if matches!(
                    outcome.status,
                    StreamBatchStatus::Completed | StreamBatchStatus::Partial
                ) =>
            {
                self.state = SessionState::CoverageVerified;
            }
            Ok(outcome) if outcome.status == StreamBatchStatus::Cancelled => {
                self.state = SessionState::Cancelled;
            }
            Ok(_) => self.state = SessionState::Interrupted,
            Err(_) => self.state = SessionState::Poisoned,
        }
        result
    }

    fn finalize_coverage_inner<S: StreamingScanSink>(
        &self,
        sink: &mut S,
        control: &dyn ScanControl,
    ) -> Result<StageBatchOutcome, StreamScanError<S::Error>> {
        let mut events = EventBuffer::new(sink, self.limits);
        let completed_directories = self
            .verified_directory_tickets
            .checked_sub(self.verified_directory_failures)
            .ok_or(StreamScanError::InvalidState(
                "directory coverage failures exceeded replayed tickets",
            ))?;
        if control.is_cancelled() {
            events.finish()?;
            return Ok(StageBatchOutcome {
                status: StreamBatchStatus::Cancelled,
                completed: completed_directories,
                failed: self.verified_directory_failures,
            });
        }
        let mut stable = self.coverage_stable;
        let mut finalization_failures = 0_u64;
        for root in &self.pending_roots {
            match snapshot_path(&root.path) {
                Ok((metadata, snapshot))
                    if metadata.file_type().is_dir() == root.is_directory
                        && snapshot == root.snapshot => {}
                Ok(_) => {
                    stable = false;
                    finalization_failures = finalization_failures.checked_add(1).ok_or(
                        StreamScanError::InvalidState("coverage failure count overflowed"),
                    )?;
                    events.push(StreamEvent::Issue(make_issue(
                        ScanIssueCode::RootChangedDuringScan,
                        root.path.clone(),
                        "scan root identity, device, or change time changed".to_owned(),
                    )))?;
                }
                Err(error) => {
                    stable = false;
                    finalization_failures = finalization_failures.checked_add(1).ok_or(
                        StreamScanError::InvalidState("coverage failure count overflowed"),
                    )?;
                    events.push(StreamEvent::Issue(make_issue(
                        ScanIssueCode::RootChangedDuringScan,
                        root.path.clone(),
                        format!("scan root could not be revalidated: {error}"),
                    )))?;
                }
            }
        }
        for root in self.roots.iter().flatten() {
            let RootAccess::File { ticket, .. } = root else {
                continue;
            };
            match self.open_file_ticket(ticket) {
                Ok(_) => {}
                Err(TicketReadError::Ticket(error)) => return Err(StreamScanError::Ticket(error)),
                Err(error) => {
                    stable = false;
                    finalization_failures = finalization_failures.checked_add(1).ok_or(
                        StreamScanError::InvalidState("coverage failure count overflowed"),
                    )?;
                    events.push(StreamEvent::Issue(error.into_issue()))?;
                }
            }
        }
        let failed = self
            .verified_directory_failures
            .checked_add(finalization_failures)
            .ok_or(StreamScanError::InvalidState(
                "coverage failure count overflowed",
            ))?;
        if stable && !self.enumeration_partial {
            let directory_manifest_digest = *self
                .verified_directory_manifest
                .clone()
                .finalize()
                .as_bytes();
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"guiying.core-coverage-seal.v1\0");
            hasher.update(self.session_id.as_bytes());
            hasher.update(&self.expected_directory_tickets.to_le_bytes());
            hasher.update(&self.verified_directory_tickets.to_le_bytes());
            hasher.update(&directory_manifest_digest);
            for root in self.roots.iter().flatten() {
                if let RootAccess::File { ticket, .. } = root {
                    hasher.update(ticket.sort_key());
                }
            }
            let seal = CoverageSeal {
                session_id: self.session_id,
                trust_scope: StreamTrustScope::CurrentCoreSessionOnly,
                directory_observations: self.expected_directory_tickets,
                directory_manifest_digest,
                seal_digest: *hasher.finalize().as_bytes(),
            };
            events.push(StreamEvent::CoverageVerified(seal))?;
            events.push(StreamEvent::Progress(ScanProgress {
                stage: ProgressStage::Complete,
                completed: self.expected_directory_tickets,
                total: Some(self.expected_directory_tickets),
                current_path: None,
            }))?;
            events.finish()?;
            Ok(StageBatchOutcome {
                status: StreamBatchStatus::Completed,
                completed: self.expected_directory_tickets,
                failed,
            })
        } else if stable {
            events.finish()?;
            Ok(StageBatchOutcome {
                status: StreamBatchStatus::Partial,
                completed: completed_directories,
                failed,
            })
        } else {
            events.finish()?;
            Ok(StageBatchOutcome {
                status: StreamBatchStatus::Interrupted,
                completed: completed_directories,
                failed,
            })
        }
    }

    fn require_readable_state<E>(&self) -> Result<(), StreamScanError<E>> {
        if self.state == SessionState::Enumerated {
            Ok(())
        } else {
            Err(StreamScanError::InvalidState(
                "operation requires a successfully enumerated live session",
            ))
        }
    }

    fn open_file_ticket(
        &self,
        ticket: &FileObservationTicket,
    ) -> Result<OpenedObservation, TicketReadError> {
        let claims = self
            .validate_ticket(&ticket.0, TicketKind::File)
            .map_err(TicketReadError::Ticket)?;
        let root = self
            .roots
            .get(claims.root_index)
            .and_then(Option::as_ref)
            .ok_or(TicketReadError::Ticket(TicketDecodeError::Malformed))?;
        match root {
            RootAccess::Directory { path, anchor } => {
                if claims.components.is_empty() {
                    return Err(TicketReadError::Ticket(TicketDecodeError::Malformed));
                }
                let full_path = join_components(path, &claims.components);
                let info = anchor
                    .bind_regular_file(&claims.components, full_path.clone())
                    .map_err(|error| map_bind_file_read_error(full_path.clone(), error))?;
                let root_relative_path = relative_path_ref(&claims.components);
                let signature = observation_source_signature(
                    self.session_id,
                    claims.root_index,
                    &root_relative_path,
                    &info.snapshot,
                    SnapshotKind::File,
                );
                if signature != claims.source_signature {
                    return Err(TicketReadError::Changed(full_path));
                }
                Ok(OpenedObservation {
                    path: full_path,
                    binding: info.binding,
                    snapshot: info.snapshot,
                    source_signature: signature,
                    session_id: self.session_id,
                    root_index: claims.root_index,
                    root_relative_path,
                })
            }
            RootAccess::File {
                path,
                binding,
                snapshot,
                ..
            } => {
                if !claims.components.is_empty() {
                    return Err(TicketReadError::Ticket(TicketDecodeError::Malformed));
                }
                let root_relative_path = relative_path_ref(&claims.components);
                let signature = observation_source_signature(
                    self.session_id,
                    claims.root_index,
                    &root_relative_path,
                    snapshot,
                    SnapshotKind::File,
                );
                if signature != claims.source_signature {
                    return Err(TicketReadError::Changed(path.clone()));
                }
                binding
                    .open_stable(snapshot)
                    .map_err(|error| map_stable_read_error(path.clone(), error))?;
                Ok(OpenedObservation {
                    path: path.clone(),
                    binding: binding.clone(),
                    snapshot: snapshot.as_ref().clone(),
                    source_signature: signature,
                    session_id: self.session_id,
                    root_index: claims.root_index,
                    root_relative_path,
                })
            }
        }
    }

    fn validate_ticket(
        &self,
        ticket: &OpaqueTicket,
        expected_kind: TicketKind,
    ) -> Result<TicketClaims, TicketDecodeError> {
        let claims = parse_ticket(&ticket.bytes, expected_kind)?;
        if claims.session_id != self.session_id {
            return Err(TicketDecodeError::WrongSession);
        }
        let payload_len = ticket
            .bytes
            .len()
            .checked_sub(TICKET_MAC_BYTES)
            .ok_or(TicketDecodeError::Malformed)?;
        let expected_mac = blake3::keyed_hash(&self.ticket_key, &ticket.bytes[..payload_len]);
        if expected_mac.as_bytes() != &ticket.bytes[payload_len..] {
            return Err(TicketDecodeError::AuthenticationFailed);
        }
        Ok(claims)
    }
}

struct StreamDirectoryFrame {
    root_index: usize,
    root_device: Option<u64>,
    depth: u16,
    directory: BoundDirectory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum TicketKind {
    File = 1,
    Directory = 2,
}

struct TicketClaims {
    session_id: StreamSessionId,
    root_index: usize,
    components: Vec<OsString>,
    source_signature: [u8; 32],
}

#[derive(Clone, Copy)]
enum SnapshotKind {
    File,
    Directory,
}

struct OpenedObservation {
    path: PathBuf,
    binding: BoundFile,
    snapshot: FileSnapshot,
    source_signature: [u8; 32],
    session_id: StreamSessionId,
    root_index: usize,
    root_relative_path: PathRef,
}

struct PendingFreshFingerprint {
    path: PathRef,
    digest: [u8; 32],
    parameters_hash: [u8; 32],
    expected_length: u64,
    bytes_read: u64,
    eof_verified: bool,
    before_source_signature: [u8; 32],
    after_source_signature: [u8; 32],
}

impl PendingFreshFingerprint {
    fn with_session(
        self,
        session_id: StreamSessionId,
        ticket_id: [u8; 32],
        origin: FreshReadOrigin,
    ) -> FreshFingerprintEvidence {
        FreshFingerprintEvidence {
            session_id,
            trust_scope: StreamTrustScope::CurrentCoreSessionOnly,
            path: self.path,
            observation_ticket_id: ticket_id,
            read_origin: origin,
            algorithm: "blake3",
            algorithm_version: 1,
            parameters_hash: self.parameters_hash,
            digest: self.digest,
            expected_length: self.expected_length,
            bytes_read: self.bytes_read,
            eof_verified: self.eof_verified,
            before_source_signature: self.before_source_signature,
            after_source_signature: self.after_source_signature,
        }
    }
}

struct PendingExactEvidence {
    left_path: PathRef,
    right_path: PathRef,
    left_expected_length: u64,
    right_expected_length: u64,
    bytes_compared: u64,
    identical: bool,
    eof_verified: bool,
    left_digest: Option<[u8; 32]>,
    right_digest: Option<[u8; 32]>,
    left_before_source_signature: [u8; 32],
    left_after_source_signature: [u8; 32],
    right_before_source_signature: [u8; 32],
    right_after_source_signature: [u8; 32],
}

impl PendingExactEvidence {
    fn with_session(
        self,
        session_id: StreamSessionId,
        left_ticket_id: [u8; 32],
        right_ticket_id: [u8; 32],
    ) -> ExactComparisonEvidence {
        ExactComparisonEvidence {
            session_id,
            trust_scope: StreamTrustScope::CurrentCoreSessionOnly,
            left_path: self.left_path,
            right_path: self.right_path,
            left_observation_ticket_id: left_ticket_id,
            right_observation_ticket_id: right_ticket_id,
            left_expected_length: self.left_expected_length,
            right_expected_length: self.right_expected_length,
            bytes_compared: self.bytes_compared,
            identical: self.identical,
            eof_verified: self.eof_verified,
            digest_algorithm: "blake3",
            digest_algorithm_version: 1,
            digest_parameters_hash: full_hash_parameters_hash(),
            left_digest: self.left_digest,
            right_digest: self.right_digest,
            left_before_source_signature: self.left_before_source_signature,
            left_after_source_signature: self.left_after_source_signature,
            right_before_source_signature: self.right_before_source_signature,
            right_after_source_signature: self.right_after_source_signature,
        }
    }
}

enum FreshReadError {
    Cancelled,
    Io(io::Error),
    Changed,
}

impl FreshReadError {
    fn into_issue(self, path: PathBuf) -> ScanIssue {
        match self {
            Self::Io(error) => make_issue(ScanIssueCode::FileUnreadable, path, error.to_string()),
            Self::Changed => make_issue(
                ScanIssueCode::ChangedDuringScan,
                path,
                "file identity or metadata changed during the fresh read".to_owned(),
            ),
            Self::Cancelled => make_issue(
                ScanIssueCode::FileUnreadable,
                path,
                "fresh read was cancelled".to_owned(),
            ),
        }
    }
}

enum ExactReadError {
    Cancelled,
    Left(PathBuf, io::Error),
    Right(PathBuf, io::Error),
    Changed(PathBuf),
}

impl ExactReadError {
    fn into_issue(self) -> ScanIssue {
        match self {
            Self::Left(path, error) | Self::Right(path, error) => make_issue(
                ScanIssueCode::ExactVerificationFailed,
                path,
                error.to_string(),
            ),
            Self::Changed(path) => make_issue(
                ScanIssueCode::ChangedDuringScan,
                path,
                "file identity or metadata changed during exact comparison".to_owned(),
            ),
            Self::Cancelled => make_issue(
                ScanIssueCode::ExactVerificationFailed,
                PathBuf::new(),
                "exact comparison was cancelled".to_owned(),
            ),
        }
    }
}

enum TicketReadError {
    Ticket(TicketDecodeError),
    Io(PathBuf, io::Error),
    NotRegular(PathBuf),
    Changed(PathBuf),
}

impl TicketReadError {
    fn into_issue(self) -> ScanIssue {
        match self {
            Self::Io(path, error) => {
                make_issue(ScanIssueCode::FileUnreadable, path, error.to_string())
            }
            Self::NotRegular(path) => make_issue(
                ScanIssueCode::UnsupportedFileType,
                path,
                "entry stopped being a regular file".to_owned(),
            ),
            Self::Changed(path) => make_issue(
                ScanIssueCode::ChangedDuringScan,
                path,
                "file no longer matches its authenticated enumeration snapshot".to_owned(),
            ),
            Self::Ticket(error) => make_issue(
                ScanIssueCode::FileUnreadable,
                PathBuf::new(),
                error.to_string(),
            ),
        }
    }
}

struct EventBuffer<'a, S: StreamingScanSink> {
    sink: &'a mut S,
    limits: StreamLimits,
    events: Vec<StreamEvent>,
    estimated_bytes: usize,
}

impl<'a, S: StreamingScanSink> EventBuffer<'a, S> {
    fn new(sink: &'a mut S, limits: StreamLimits) -> Self {
        Self {
            sink,
            limits,
            events: Vec::with_capacity(limits.max_events_per_batch),
            estimated_bytes: 0,
        }
    }

    fn push(&mut self, event: StreamEvent) -> Result<(), StreamScanError<S::Error>> {
        let size = estimated_event_bytes(&event);
        if size > self.limits.max_bytes_per_batch {
            return Err(StreamScanError::EventTooLarge {
                estimated: size,
                maximum: self.limits.max_bytes_per_batch,
            });
        }
        if !self.events.is_empty()
            && (self.events.len() == self.limits.max_events_per_batch
                || self.estimated_bytes.saturating_add(size) > self.limits.max_bytes_per_batch)
        {
            self.flush()?;
        }
        self.estimated_bytes = self.estimated_bytes.saturating_add(size);
        self.events.push(event);
        if self.events.len() == self.limits.max_events_per_batch {
            self.flush()?;
        }
        Ok(())
    }

    fn finish(mut self) -> Result<(), StreamScanError<S::Error>> {
        self.flush()
    }

    fn flush(&mut self) -> Result<(), StreamScanError<S::Error>> {
        if self.events.is_empty() {
            return Ok(());
        }
        self.sink
            .write_batch(&self.events)
            .map_err(StreamScanError::Sink)?;
        self.events.clear();
        self.estimated_bytes = 0;
        Ok(())
    }
}

fn validate_input_len<E>(len: usize) -> Result<(), StreamScanError<E>> {
    if len <= STREAM_INPUT_BATCH_HARD_MAX {
        Ok(())
    } else {
        Err(StreamScanError::InputBatchTooLarge {
            supplied: len,
            maximum: STREAM_INPUT_BATCH_HARD_MAX,
        })
    }
}

fn enumeration_outcome(
    status: StreamBatchStatus,
    stats: ScanStats,
    directory_observations: u64,
) -> StreamingEnumerationOutcome {
    StreamingEnumerationOutcome {
        status,
        stats,
        directory_observations,
    }
}

fn emit_issue<S: StreamingScanSink>(
    events: &mut EventBuffer<'_, S>,
    stats: &mut ScanStats,
    partial: &mut bool,
    issue: ScanIssue,
) -> Result<(), StreamScanError<S::Error>> {
    stats.issues = stats.issues.saturating_add(1);
    if issue_makes_partial(issue.code) {
        *partial = true;
    }
    events.push(StreamEvent::Issue(issue))
}

fn issue_makes_partial(code: ScanIssueCode) -> bool {
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

fn make_issue(code: ScanIssueCode, path: PathBuf, detail: String) -> ScanIssue {
    ScanIssue {
        code,
        path: PathRef::from_path(&path),
        detail: truncate_utf8(detail, ISSUE_DETAIL_BYTES_MAX),
    }
}

fn make_root_observation(
    session_id: StreamSessionId,
    root_index: usize,
    path: PathBuf,
    kind: StreamRootKind,
    snapshot: &FileSnapshot,
) -> StreamRootObservation {
    let root_relative_path = relative_path_ref(&[]);
    let snapshot_kind = match kind {
        StreamRootKind::Directory => SnapshotKind::Directory,
        StreamRootKind::RegularFile => SnapshotKind::File,
    };
    StreamRootObservation {
        root_index: bounded_root_index(root_index),
        path: PathRef::from_path(&path),
        kind,
        size: snapshot.len,
        allocated_size: snapshot.allocated_size,
        observed_accessed: snapshot.accessed_timestamp(),
        file_id: snapshot.file_id,
        generation: snapshot.generation(),
        mode: snapshot.mode(),
        hard_link_count: snapshot.hard_link_count,
        created: snapshot.created_timestamp(),
        modified: snapshot.modified_timestamp(),
        change_time: snapshot.change_timestamp(),
        source_signature: observation_source_signature(
            session_id,
            root_index,
            &root_relative_path,
            snapshot,
            snapshot_kind,
        ),
    }
}

fn directory_bind_issue(path: PathBuf, error: BindDirectoryError, root: bool) -> ScanIssue {
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
    make_issue(code, path, detail)
}

fn file_bind_issue(path: PathBuf, error: BindFileError) -> ScanIssue {
    match error {
        BindFileError::Io(error) => {
            make_issue(ScanIssueCode::FileUnreadable, path, error.to_string())
        }
        BindFileError::NotRegular => make_issue(
            ScanIssueCode::ChangedDuringScan,
            path,
            "entry stopped being a regular file before it was bound".to_owned(),
        ),
    }
}

fn stable_open_issue(path: PathBuf, error: StableOpenError) -> ScanIssue {
    match error {
        StableOpenError::Io(error) => {
            make_issue(ScanIssueCode::FileUnreadable, path, error.to_string())
        }
        StableOpenError::NotRegular => make_issue(
            ScanIssueCode::UnsupportedFileType,
            path,
            "scan root stopped being a regular file".to_owned(),
        ),
        StableOpenError::Changed => make_issue(
            ScanIssueCode::RootChangedDuringScan,
            path,
            "scan root changed before its descriptor was bound".to_owned(),
        ),
    }
}

fn map_bind_file_read_error(path: PathBuf, error: BindFileError) -> TicketReadError {
    match error {
        BindFileError::Io(error) => TicketReadError::Io(path, error),
        BindFileError::NotRegular => TicketReadError::NotRegular(path),
    }
}

fn map_stable_read_error(path: PathBuf, error: StableOpenError) -> TicketReadError {
    match error {
        StableOpenError::Io(error) => TicketReadError::Io(path, error),
        StableOpenError::NotRegular => TicketReadError::NotRegular(path),
        StableOpenError::Changed => TicketReadError::Changed(path),
    }
}

fn read_sample_fresh(
    opened: &OpenedObservation,
    sample_bytes: usize,
    control: &dyn ScanControl,
) -> Result<PendingFreshFingerprint, FreshReadError> {
    let (mut file, before) = opened
        .binding
        .open_stable(&opened.snapshot)
        .map_err(map_fresh_open_error)?;
    let chunk = before.len.min(sample_bytes as u64) as usize;
    let mut offsets = vec![0_u64];
    if before.len > chunk as u64 {
        offsets.push(before.len / 2 - chunk as u64 / 2);
        offsets.push(before.len - chunk as u64);
    }
    offsets.sort_unstable();
    offsets.dedup();

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying-sample-v1\0");
    hasher.update(&before.len.to_le_bytes());
    hasher.update(&(sample_bytes as u64).to_le_bytes());
    let mut parameters = blake3::Hasher::new();
    parameters.update(b"guiying.sample-parameters.v1\0");
    parameters.update(&before.len.to_le_bytes());
    parameters.update(&(sample_bytes as u64).to_le_bytes());
    let mut buffer = vec![0_u8; chunk];
    let mut bytes_read = 0_u64;
    for offset in offsets {
        if control.is_cancelled() {
            return Err(FreshReadError::Cancelled);
        }
        hasher.update(&offset.to_le_bytes());
        hasher.update(&(chunk as u64).to_le_bytes());
        parameters.update(&offset.to_le_bytes());
        parameters.update(&(chunk as u64).to_le_bytes());
        file.seek(SeekFrom::Start(offset))
            .map_err(FreshReadError::Io)?;
        read_exact_cancel(&mut file, &mut buffer, control).map_err(|error| match error {
            CancelReadError::Cancelled => FreshReadError::Cancelled,
            CancelReadError::Io(error) => FreshReadError::Io(error),
        })?;
        hasher.update(&buffer);
        bytes_read = bytes_read.saturating_add(chunk as u64);
    }
    let after = verified_after_signature(opened, &file, &before)?;
    Ok(PendingFreshFingerprint {
        path: PathRef::from_path(&opened.path),
        digest: *hasher.finalize().as_bytes(),
        parameters_hash: *parameters.finalize().as_bytes(),
        expected_length: before.len,
        bytes_read,
        eof_verified: false,
        before_source_signature: opened.source_signature,
        after_source_signature: after,
    })
}

fn read_full_fresh(
    opened: &OpenedObservation,
    buffer_bytes: usize,
    control: &dyn ScanControl,
) -> Result<PendingFreshFingerprint, FreshReadError> {
    let (mut file, before) = opened
        .binding
        .open_stable(&opened.snapshot)
        .map_err(map_fresh_open_error)?;
    file.seek(SeekFrom::Start(0)).map_err(FreshReadError::Io)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; buffer_bytes];
    let mut bytes_read = 0_u64;
    while bytes_read < before.len {
        if control.is_cancelled() {
            return Err(FreshReadError::Cancelled);
        }
        let remaining = before.len - bytes_read;
        let chunk = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let read = read_retry(&mut file, &mut buffer[..chunk]).map_err(FreshReadError::Io)?;
        if read == 0 {
            return Err(FreshReadError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("expected {} bytes, read {bytes_read}", before.len),
            )));
        }
        hasher.update(&buffer[..read]);
        bytes_read = bytes_read.saturating_add(read as u64);
    }
    ensure_eof(&mut file).map_err(FreshReadError::Io)?;
    let after = verified_after_signature(opened, &file, &before)?;
    Ok(PendingFreshFingerprint {
        path: PathRef::from_path(&opened.path),
        digest: *hasher.finalize().as_bytes(),
        parameters_hash: full_hash_parameters_hash(),
        expected_length: before.len,
        bytes_read,
        eof_verified: true,
        before_source_signature: opened.source_signature,
        after_source_signature: after,
    })
}

fn compare_opened_fresh(
    left: &OpenedObservation,
    right: &OpenedObservation,
    configured_buffer_bytes: usize,
    control: &dyn ScanControl,
) -> Result<PendingExactEvidence, ExactReadError> {
    let (mut left_file, left_before) = left
        .binding
        .open_stable(&left.snapshot)
        .map_err(|error| map_exact_open_error(left.path.clone(), error))?;
    let (mut right_file, right_before) = right
        .binding
        .open_stable(&right.snapshot)
        .map_err(|error| map_exact_open_error(right.path.clone(), error))?;
    if left_before.len != right_before.len {
        let left_after = verified_after_signature_exact(left, &left_file, &left_before)?;
        let right_after = verified_after_signature_exact(right, &right_file, &right_before)?;
        return Ok(PendingExactEvidence {
            left_path: PathRef::from_path(&left.path),
            right_path: PathRef::from_path(&right.path),
            left_expected_length: left_before.len,
            right_expected_length: right_before.len,
            bytes_compared: 0,
            identical: false,
            eof_verified: false,
            left_digest: None,
            right_digest: None,
            left_before_source_signature: left.source_signature,
            left_after_source_signature: left_after,
            right_before_source_signature: right.source_signature,
            right_after_source_signature: right_after,
        });
    }
    let buffer_bytes = configured_buffer_bytes.min(EXACT_BUFFER_BYTES_MAX).max(1);
    let mut left_buffer = vec![0_u8; buffer_bytes];
    let mut right_buffer = vec![0_u8; buffer_bytes];
    let mut left_hasher = blake3::Hasher::new();
    let mut right_hasher = blake3::Hasher::new();
    let mut bytes_compared = 0_u64;
    let mut identical = true;
    while bytes_compared < left_before.len {
        if control.is_cancelled() {
            return Err(ExactReadError::Cancelled);
        }
        let remaining = left_before.len - bytes_compared;
        let chunk = remaining.min(buffer_bytes as u64) as usize;
        read_exact_cancel(&mut left_file, &mut left_buffer[..chunk], control)
            .map_err(|error| map_cancel_exact_error(left.path.clone(), error, true))?;
        read_exact_cancel(&mut right_file, &mut right_buffer[..chunk], control)
            .map_err(|error| map_cancel_exact_error(right.path.clone(), error, false))?;
        left_hasher.update(&left_buffer[..chunk]);
        right_hasher.update(&right_buffer[..chunk]);
        if let Some(position) = left_buffer[..chunk]
            .iter()
            .zip(&right_buffer[..chunk])
            .position(|(left_byte, right_byte)| left_byte != right_byte)
        {
            bytes_compared = bytes_compared.saturating_add(position as u64 + 1);
            identical = false;
            break;
        }
        bytes_compared = bytes_compared.saturating_add(chunk as u64);
    }
    if identical {
        ensure_eof(&mut left_file)
            .map_err(|error| ExactReadError::Left(left.path.clone(), error))?;
        ensure_eof(&mut right_file)
            .map_err(|error| ExactReadError::Right(right.path.clone(), error))?;
    }
    let left_after = verified_after_signature_exact(left, &left_file, &left_before)?;
    let right_after = verified_after_signature_exact(right, &right_file, &right_before)?;
    Ok(PendingExactEvidence {
        left_path: PathRef::from_path(&left.path),
        right_path: PathRef::from_path(&right.path),
        left_expected_length: left_before.len,
        right_expected_length: right_before.len,
        bytes_compared,
        identical,
        eof_verified: identical,
        left_digest: identical.then(|| *left_hasher.finalize().as_bytes()),
        right_digest: identical.then(|| *right_hasher.finalize().as_bytes()),
        left_before_source_signature: left.source_signature,
        left_after_source_signature: left_after,
        right_before_source_signature: right.source_signature,
        right_after_source_signature: right_after,
    })
}

fn verified_after_signature(
    opened: &OpenedObservation,
    file: &File,
    before: &FileSnapshot,
) -> Result<[u8; 32], FreshReadError> {
    match opened.binding.snapshot_after_read(file, before) {
        Ok(Some(after)) => Ok(observation_source_signature(
            opened.session_id,
            opened.root_index,
            &opened.root_relative_path,
            &after,
            SnapshotKind::File,
        )),
        Ok(None) => Err(FreshReadError::Changed),
        Err(error) => Err(FreshReadError::Io(error)),
    }
}

fn verified_after_signature_exact(
    opened: &OpenedObservation,
    file: &File,
    before: &FileSnapshot,
) -> Result<[u8; 32], ExactReadError> {
    match opened.binding.snapshot_after_read(file, before) {
        Ok(Some(after)) => Ok(observation_source_signature(
            opened.session_id,
            opened.root_index,
            &opened.root_relative_path,
            &after,
            SnapshotKind::File,
        )),
        Ok(None) => Err(ExactReadError::Changed(opened.path.clone())),
        Err(error) => Err(ExactReadError::Left(opened.path.clone(), error)),
    }
}

fn map_fresh_open_error(error: StableOpenError) -> FreshReadError {
    match error {
        StableOpenError::Io(error) => FreshReadError::Io(error),
        StableOpenError::NotRegular | StableOpenError::Changed => FreshReadError::Changed,
    }
}

fn map_exact_open_error(path: PathBuf, error: StableOpenError) -> ExactReadError {
    match error {
        StableOpenError::Io(error) => ExactReadError::Left(path, error),
        StableOpenError::NotRegular | StableOpenError::Changed => ExactReadError::Changed(path),
    }
}

enum CancelReadError {
    Cancelled,
    Io(io::Error),
}

fn read_exact_cancel(
    reader: &mut impl Read,
    mut destination: &mut [u8],
    control: &dyn ScanControl,
) -> Result<(), CancelReadError> {
    let expected = destination.len();
    let mut actual = 0_usize;
    while !destination.is_empty() {
        if control.is_cancelled() {
            return Err(CancelReadError::Cancelled);
        }
        match reader.read(destination) {
            Ok(0) => {
                return Err(CancelReadError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("expected {expected} bytes, read {actual}"),
                )))
            }
            Ok(read) => {
                actual = actual.saturating_add(read);
                destination = &mut destination[read..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(CancelReadError::Io(error)),
        }
    }
    Ok(())
}

fn read_retry(reader: &mut impl Read, destination: &mut [u8]) -> io::Result<usize> {
    loop {
        match reader.read(destination) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

fn ensure_eof(reader: &mut impl Read) -> io::Result<()> {
    let mut extra = [0_u8; 1];
    loop {
        match reader.read(&mut extra) {
            Ok(0) => return Ok(()),
            Ok(read) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("file contains {read} byte beyond its observed length"),
                ))
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

fn map_cancel_exact_error(path: PathBuf, error: CancelReadError, left: bool) -> ExactReadError {
    match error {
        CancelReadError::Cancelled => ExactReadError::Cancelled,
        CancelReadError::Io(error) if left => ExactReadError::Left(path, error),
        CancelReadError::Io(error) => ExactReadError::Right(path, error),
    }
}

fn snapshot_signature(snapshot: &FileSnapshot, kind: SnapshotKind) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying.core-file-snapshot.v1\0");
    hasher.update(&[match kind {
        SnapshotKind::File => 1,
        SnapshotKind::Directory => 2,
    }]);
    hasher.update(&snapshot.len.to_le_bytes());
    update_optional_u64(&mut hasher, snapshot.allocated_size);
    update_timestamp(&mut hasher, snapshot.modified_timestamp());
    update_timestamp(&mut hasher, snapshot.created_timestamp());
    update_optional_u64(&mut hasher, snapshot.file_id.map(|id| id.device));
    update_optional_u64(&mut hasher, snapshot.file_id.map(|id| id.inode));
    update_optional_u64(&mut hasher, snapshot.hard_link_count);
    update_optional_u64(&mut hasher, snapshot.mode().map(u64::from));
    update_optional_u64(&mut hasher, snapshot.generation().map(u64::from));
    #[cfg(unix)]
    {
        hasher.update(&snapshot.change_seconds.to_le_bytes());
        hasher.update(&snapshot.change_nanoseconds.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn observation_source_signature(
    session_id: StreamSessionId,
    root_index: usize,
    root_relative_path: &PathRef,
    snapshot: &FileSnapshot,
    kind: SnapshotKind,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying.core-observation-source.v1\0");
    hasher.update(session_id.as_bytes());
    hasher.update(&bounded_root_index(root_index).to_le_bytes());
    let encoding = match root_relative_path.encoding {
        crate::PathEncoding::UnixBytes => 1_u8,
        crate::PathEncoding::WindowsUtf16Le => 2_u8,
        crate::PathEncoding::Utf8 => 3_u8,
    };
    hasher.update(&[encoding]);
    hasher.update(&(root_relative_path.raw_base64.len() as u64).to_le_bytes());
    hasher.update(root_relative_path.raw_base64.as_bytes());
    hasher.update(&snapshot_signature(snapshot, kind));
    *hasher.finalize().as_bytes()
}

fn bounded_root_index(root_index: usize) -> u16 {
    debug_assert!(root_index < STREAM_ROOTS_HARD_MAX);
    root_index as u16
}

fn relative_path_ref(components: &[OsString]) -> PathRef {
    let mut path = PathBuf::new();
    for component in components {
        path.push(component);
    }
    PathRef::from_path(&path)
}

fn update_timestamp(hasher: &mut blake3::Hasher, value: Option<FileTimestamp>) {
    match value {
        Some(value) => {
            hasher.update(&[1]);
            hasher.update(&value.seconds.to_le_bytes());
            hasher.update(&value.nanoseconds.to_le_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

fn update_optional_u64(hasher: &mut blake3::Hasher, value: Option<u64>) {
    match value {
        Some(value) => {
            hasher.update(&[1]);
            hasher.update(&value.to_le_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

fn parse_ticket(
    bytes: &[u8],
    expected_kind: TicketKind,
) -> Result<TicketClaims, TicketDecodeError> {
    let opaque = OpaqueTicket::from_untrusted_bytes(bytes, expected_kind)?;
    let payload_len = opaque
        .bytes
        .len()
        .checked_sub(TICKET_MAC_BYTES)
        .ok_or(TicketDecodeError::Malformed)?;
    let mut cursor = TicketCursor::new(&opaque.bytes[..payload_len]);
    if cursor.take(4)? != TICKET_MAGIC
        || cursor.u8()? != TICKET_VERSION
        || cursor.u8()? != expected_kind as u8
    {
        return Err(TicketDecodeError::Malformed);
    }
    let encoding = cursor.u8()?;
    if encoding != native_path_encoding_tag() {
        return Err(TicketDecodeError::UnsupportedPathEncoding);
    }
    if cursor.u8()? != 0 {
        return Err(TicketDecodeError::Malformed);
    }
    let mut session_id = [0_u8; 32];
    session_id.copy_from_slice(cursor.take(32)?);
    let root_index = cursor.u16()? as usize;
    let component_count = cursor.u16()? as usize;
    if component_count > 512 {
        return Err(TicketDecodeError::TooLarge);
    }
    let mut components = Vec::with_capacity(component_count);
    for _ in 0..component_count {
        let len = cursor.u32()? as usize;
        let component = decode_component(cursor.take(len)?)?;
        validate_component(&component)?;
        components.push(component);
    }
    let mut source_signature = [0_u8; 32];
    source_signature.copy_from_slice(cursor.take(32)?);
    if !cursor.is_empty() {
        return Err(TicketDecodeError::Malformed);
    }
    Ok(TicketClaims {
        session_id: StreamSessionId(session_id),
        root_index,
        components,
        source_signature,
    })
}

struct TicketCursor<'a> {
    remaining: &'a [u8],
}

impl<'a> TicketCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], TicketDecodeError> {
        if count > self.remaining.len() {
            return Err(TicketDecodeError::Malformed);
        }
        let (value, remaining) = self.remaining.split_at(count);
        self.remaining = remaining;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, TicketDecodeError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, TicketDecodeError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| TicketDecodeError::Malformed)?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, TicketDecodeError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| TicketDecodeError::Malformed)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

fn ticket_sort_key(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying.core-ticket-id.v1\0");
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn xor_digest(accumulator: &mut [u8; 32], digest: &[u8; 32]) {
    for (target, value) in accumulator.iter_mut().zip(digest) {
        *target ^= value;
    }
}

fn directory_manifest_hasher(session_id: StreamSessionId) -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying.core-directory-manifest.v1\0");
    hasher.update(session_id.as_bytes());
    hasher
}

fn full_hash_parameters_hash() -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying.blake3-full-content.v1\0");
    *hasher.finalize().as_bytes()
}

#[cfg(unix)]
fn native_path_encoding_tag() -> u8 {
    1
}

#[cfg(windows)]
fn native_path_encoding_tag() -> u8 {
    2
}

#[cfg(not(any(unix, windows)))]
fn native_path_encoding_tag() -> u8 {
    3
}

#[cfg(unix)]
fn encode_component<E>(component: &OsStr) -> Result<Vec<u8>, StreamScanError<E>> {
    use std::os::unix::ffi::OsStrExt;
    Ok(component.as_bytes().to_vec())
}

#[cfg(windows)]
fn encode_component<E>(component: &OsStr) -> Result<Vec<u8>, StreamScanError<E>> {
    use std::os::windows::ffi::OsStrExt;
    Ok(component.encode_wide().flat_map(u16::to_le_bytes).collect())
}

#[cfg(not(any(unix, windows)))]
fn encode_component<E>(component: &OsStr) -> Result<Vec<u8>, StreamScanError<E>> {
    component
        .to_str()
        .map(|value| value.as_bytes().to_vec())
        .ok_or(StreamScanError::Ticket(
            TicketDecodeError::UnsupportedPathEncoding,
        ))
}

#[cfg(unix)]
fn decode_component(bytes: &[u8]) -> Result<OsString, TicketDecodeError> {
    use std::os::unix::ffi::OsStringExt;
    Ok(OsString::from_vec(bytes.to_vec()))
}

#[cfg(windows)]
fn decode_component(bytes: &[u8]) -> Result<OsString, TicketDecodeError> {
    use std::os::windows::ffi::OsStringExt;
    if bytes.len() % 2 != 0 {
        return Err(TicketDecodeError::Malformed);
    }
    let wide: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    Ok(OsString::from_wide(&wide))
}

#[cfg(not(any(unix, windows)))]
fn decode_component(bytes: &[u8]) -> Result<OsString, TicketDecodeError> {
    String::from_utf8(bytes.to_vec())
        .map(OsString::from)
        .map_err(|_| TicketDecodeError::Malformed)
}

fn validate_component(component: &OsStr) -> Result<(), TicketDecodeError> {
    let path = Path::new(component);
    if component.is_empty()
        || path == Path::new(".")
        || path == Path::new("..")
        || path.components().count() != 1
    {
        return Err(TicketDecodeError::Malformed);
    }
    Ok(())
}

fn join_components(root: &Path, components: &[OsString]) -> PathBuf {
    let mut path = root.to_path_buf();
    for component in components {
        path.push(component);
    }
    path
}

fn estimated_event_bytes(event: &StreamEvent) -> usize {
    const BASE: usize = 128;
    match event {
        StreamEvent::RootObservation(observation) => {
            BASE.saturating_add(path_ref_bytes(&observation.path))
        }
        StreamEvent::FileObservation(observation) => BASE
            .saturating_add(path_ref_bytes(&observation.path))
            .saturating_add(path_ref_bytes(&observation.root_relative_path))
            .saturating_add(observation.ticket.as_bytes().len()),
        StreamEvent::DirectoryObservation(observation) => BASE
            .saturating_add(path_ref_bytes(&observation.path))
            .saturating_add(path_ref_bytes(&observation.root_relative_path))
            .saturating_add(observation.ticket.as_bytes().len()),
        StreamEvent::Issue(issue) => BASE
            .saturating_add(path_ref_bytes(&issue.path))
            .saturating_add(issue.detail.len()),
        StreamEvent::Progress(progress) => {
            BASE.saturating_add(progress.current_path.as_ref().map_or(0, path_ref_bytes))
        }
        StreamEvent::FreshFingerprint(evidence) => {
            BASE.saturating_add(path_ref_bytes(evidence.path()))
        }
        StreamEvent::ExactComparison(evidence) => BASE
            .saturating_add(path_ref_bytes(evidence.left_path()))
            .saturating_add(path_ref_bytes(evidence.right_path())),
        StreamEvent::EnumerationFinished(_) | StreamEvent::CoverageVerified(_) => BASE,
    }
}

fn path_ref_bytes(path: &PathRef) -> usize {
    path.display
        .len()
        .saturating_add(path.raw_base64.len())
        .saturating_add(32)
}

fn truncate_utf8(mut value: String, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value;
    }
    let mut boundary = max_bytes;
    while !value.is_char_boundary(boundary) {
        boundary = boundary.saturating_sub(1);
    }
    value.truncate(boundary);
    value
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, ErrorKind};

    use super::{ensure_eof, read_exact_cancel, CancelReadError};
    use crate::NoopScanControl;

    #[test]
    fn bounded_exact_read_rejects_short_input() {
        let mut input = Cursor::new(b"abc");
        let mut output = [0_u8; 4];
        let error = read_exact_cancel(&mut input, &mut output, &NoopScanControl)
            .expect_err("short input must fail closed");
        assert!(matches!(
            error,
            CancelReadError::Io(error) if error.kind() == ErrorKind::UnexpectedEof
        ));
    }

    #[test]
    fn eof_check_rejects_extra_bytes() {
        let mut input = Cursor::new(b"x");
        let error = ensure_eof(&mut input).expect_err("extra input must fail closed");
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[cfg(unix)]
    #[test]
    fn root_relative_path_preserves_non_utf8_components() {
        use std::ffi::OsString;
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        let components = [
            OsString::from("album"),
            OsString::from_vec(b"photo-\xff.jpg".to_vec()),
        ];
        let relative = super::relative_path_ref(&components)
            .to_path_buf()
            .expect("decode native path");

        assert_eq!(relative.as_os_str().as_bytes(), b"album/photo-\xff.jpg");
    }
}
