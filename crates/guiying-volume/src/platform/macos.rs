use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{AtFlags, FileType, Mode, OFlags};

use super::BindParts;
use crate::{
    FileObjectIdentity, MountObservation, NativePathEncoding, NativeUuid, NativeValue,
    ReadOnlyFormatCapabilities, RootObjectIdentity, SpaceObservation, VolumeError,
};

const UUID_BUFFER_BYTES: usize = 4 + 16;
const CAPABILITIES_BUFFER_BYTES: usize = 4 + 32;

#[derive(Clone, Debug, Eq, PartialEq)]
struct MountSignature<Fsid = libc::fsid_t> {
    filesystem_id: Fsid,
    mount_point: Vec<u8>,
    mount_source: Vec<u8>,
    filesystem_type: Vec<u8>,
    filesystem_type_number: u32,
    filesystem_subtype: u32,
    flags: u32,
    extended_flags: u32,
    owner: u32,
}

struct MountSnapshot {
    signature: MountSignature,
    space: SpaceObservation,
}

pub(crate) struct PlatformSession {
    root_fd: OwnedFd,
    root_path: PathBuf,
    root_identity: RootObjectIdentity,
    mount_signature: MountSignature,
    native_uuid: Option<NativeUuid>,
    format_capabilities: ReadOnlyFormatCapabilities,
}

pub(crate) fn bind(root: &Path) -> Result<(PlatformSession, BindParts), VolumeError> {
    validate_root_argument(root)?;
    let path_stat = rustix::fs::statat(rustix::fs::CWD, root, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| VolumeError::io("inspecting the selected root", error))?;
    if FileType::from_raw_mode(path_stat.st_mode) == FileType::Symlink {
        return Err(VolumeError::RootSymlink);
    }
    if FileType::from_raw_mode(path_stat.st_mode) != FileType::Directory {
        return Err(VolumeError::RootNotDirectory);
    }
    let path_identity = root_identity_from_stat(&path_stat)?;

    let root_fd = rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| VolumeError::io("binding the selected root", error))?;
    let before = snapshot_root(root_fd.as_fd())?;
    if before != path_identity {
        return Err(VolumeError::RootChangedDuringBind);
    }
    ensure_directory(before.mode)?;
    let mount_before = mount_snapshot(root_fd.as_fd())?;
    let native_uuid_before = query_native_uuid(root_fd.as_fd())?;
    let format_capabilities_before =
        query_format_capabilities(root_fd.as_fd())?.unwrap_or_default();
    let format_capabilities_after = query_format_capabilities(root_fd.as_fd())?.unwrap_or_default();
    let native_uuid_after = query_native_uuid(root_fd.as_fd())?;
    let mount_after = mount_snapshot(root_fd.as_fd())?;
    let after = snapshot_root(root_fd.as_fd())?;

    if before != after {
        return Err(VolumeError::RootChangedDuringBind);
    }
    if mount_before.signature != mount_after.signature {
        return Err(VolumeError::MountSessionChanged);
    }
    if native_uuid_before != native_uuid_after
        || format_capabilities_before != format_capabilities_after
    {
        return Err(VolumeError::MountSessionChanged);
    }
    verify_path_still_names_root(root, &after)?;

    let native_uuid = native_uuid_after;
    let format_capabilities = format_capabilities_after;
    let signature = mount_after.signature;
    let mount_point = NativeValue::from_raw(&signature.mount_point, NativePathEncoding::UnixBytes);
    let mount_source =
        NativeValue::from_raw(&signature.mount_source, NativePathEncoding::UnixBytes);
    let filesystem_type =
        NativeValue::from_raw(&signature.filesystem_type, NativePathEncoding::UnixBytes);
    let flags = signature.flags;
    let mount = MountObservation::new(
        mount_point,
        mount_source,
        filesystem_type,
        u64::from(flags),
        flags & libc::MNT_RDONLY as u32 != 0,
        Some(flags & libc::MNT_LOCAL as u32 != 0),
        mount_after.space,
    );
    let parts = BindParts {
        root_identity: after,
        mount,
        mount_source_raw: signature.mount_source.clone(),
        filesystem_type_raw: signature.filesystem_type.clone(),
        native_uuid,
        format_capabilities,
    };
    let session = PlatformSession {
        root_fd,
        root_path: root.to_path_buf(),
        root_identity: after,
        mount_signature: signature,
        native_uuid,
        format_capabilities,
    };
    Ok((session, parts))
}

pub(crate) fn revalidate(session: &PlatformSession) -> Result<(), VolumeError> {
    let before = snapshot_root(session.root_fd.as_fd())?;
    if before != session.root_identity {
        return Err(VolumeError::RootBindingChanged);
    }
    let mount_before = mount_snapshot(session.root_fd.as_fd())?;
    if mount_before.signature != session.mount_signature {
        return Err(VolumeError::MountSessionChanged);
    }
    let current_uuid = query_native_uuid(session.root_fd.as_fd())?;
    if current_uuid != session.native_uuid {
        return Err(VolumeError::MountSessionChanged);
    }
    let current_capabilities =
        query_format_capabilities(session.root_fd.as_fd())?.unwrap_or_default();
    if current_capabilities != session.format_capabilities {
        return Err(VolumeError::MountSessionChanged);
    }
    verify_path_still_names_root(&session.root_path, &session.root_identity)?;
    let capabilities_after =
        query_format_capabilities(session.root_fd.as_fd())?.unwrap_or_default();
    let uuid_after = query_native_uuid(session.root_fd.as_fd())?;
    let after = snapshot_root(session.root_fd.as_fd())?;
    let mount_after = mount_snapshot(session.root_fd.as_fd())?;
    if after != before {
        return Err(VolumeError::RootBindingChanged);
    }
    if mount_after.signature != mount_before.signature {
        return Err(VolumeError::MountSessionChanged);
    }
    if capabilities_after != current_capabilities || uuid_after != current_uuid {
        return Err(VolumeError::MountSessionChanged);
    }
    Ok(())
}

pub(crate) fn open_regular_file(
    session: &PlatformSession,
    components: &[&[u8]],
) -> Result<(File, FileObjectIdentity), VolumeError> {
    if components.is_empty() {
        return Err(crate::PathError::RootIsNotAFile.into());
    }
    revalidate(session)?;

    let mut current_directory: Option<OwnedFd> = None;
    for (index, component) in components[..components.len() - 1].iter().enumerate() {
        let parent = current_directory
            .as_ref()
            .map_or_else(|| session.root_fd.as_fd(), AsFd::as_fd);
        let opened = rustix::fs::openat(
            parent,
            OsStr::from_bytes(component),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| VolumeError::UnsafePathResolution {
            component_index: index,
            source: error.into(),
        })?;
        let stat = rustix::fs::fstat(&opened)
            .map_err(|error| VolumeError::io("checking a relative directory", error))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
            return Err(VolumeError::UnsafePathResolution {
                component_index: index,
                source: io::Error::new(io::ErrorKind::InvalidInput, "component is not a directory"),
            });
        }
        verify_opened_mount_boundary(session, opened.as_fd(), device_to_u64(stat.st_dev)?)?;
        current_directory = Some(opened);
    }

    let final_index = components.len() - 1;
    let parent = current_directory
        .as_ref()
        .map_or_else(|| session.root_fd.as_fd(), AsFd::as_fd);
    let preliminary_stat = rustix::fs::statat(
        parent,
        OsStr::from_bytes(components[final_index]),
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|error| VolumeError::UnsafePathResolution {
        component_index: final_index,
        source: error.into(),
    })?;
    let preliminary_type = FileType::from_raw_mode(preliminary_stat.st_mode);
    if preliminary_type == FileType::Symlink {
        return Err(VolumeError::UnsafePathResolution {
            component_index: final_index,
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "final component is a symbolic link",
            ),
        });
    }
    if preliminary_type != FileType::RegularFile {
        return Err(VolumeError::NotRegularFile);
    }
    let preliminary_identity = file_identity_from_stat(&preliminary_stat)?;
    if preliminary_identity.device != session.root_identity.device {
        return Err(VolumeError::CrossedMountBoundary);
    }
    let descriptor = rustix::fs::openat(
        parent,
        OsStr::from_bytes(components[final_index]),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOCTTY,
        Mode::empty(),
    )
    .map_err(|error| VolumeError::UnsafePathResolution {
        component_index: final_index,
        source: error.into(),
    })?;
    let file = File::from(descriptor);
    let identity = snapshot_file(&file)?;
    if file_type(identity.mode)? != FileType::RegularFile {
        return Err(VolumeError::NotRegularFile);
    }
    if identity.device != session.root_identity.device {
        return Err(VolumeError::CrossedMountBoundary);
    }
    verify_opened_mount_boundary(session, file.as_fd(), identity.device)?;
    if identity != preliminary_identity {
        return Err(VolumeError::FileChangedDuringOpen);
    }
    revalidate(session)?;
    Ok((file, identity))
}

pub(crate) fn snapshot_file(file: &File) -> Result<FileObjectIdentity, VolumeError> {
    let stat = rustix::fs::fstat(file)
        .map_err(|error| VolumeError::io("checking an opened file", error))?;
    file_identity_from_stat(&stat)
}

fn file_identity_from_stat(stat: &rustix::fs::Stat) -> Result<FileObjectIdentity, VolumeError> {
    let size = u64::try_from(stat.st_size)
        .map_err(|_| VolumeError::MalformedSystemMetadata { field: "file size" })?;
    Ok(FileObjectIdentity {
        device: device_to_u64(stat.st_dev)?,
        inode: stat.st_ino,
        generation: stat.st_gen,
        mode: u32::from(stat.st_mode),
        hard_link_count: u64::from(stat.st_nlink),
        size,
        birth_time_seconds: stat.st_birthtime,
        birth_time_nanoseconds: nanoseconds(stat.st_birthtime_nsec, "birthtime")?,
        modified_time_seconds: stat.st_mtime,
        modified_time_nanoseconds: nanoseconds(stat.st_mtime_nsec, "mtime")?,
        change_time_seconds: stat.st_ctime,
        change_time_nanoseconds: nanoseconds(stat.st_ctime_nsec, "ctime")?,
    })
}

fn validate_root_argument(root: &Path) -> Result<(), VolumeError> {
    if !root.is_absolute() {
        return Err(VolumeError::RootNotAbsolute);
    }
    let raw = root.as_os_str().as_bytes();
    if raw.len() > crate::MAX_ROOT_PATH_BYTES {
        return Err(VolumeError::RootPathTooLong {
            limit: crate::MAX_ROOT_PATH_BYTES,
        });
    }
    if raw.contains(&0) {
        return Err(VolumeError::RootContainsNul);
    }
    if raw == b"/" {
        return Ok(());
    }

    for component in raw[1..].split(|byte| *byte == b'/') {
        if component.is_empty() {
            return Err(VolumeError::RootHasEmptyComponent);
        }
        if matches!(component, b"." | b"..") {
            return Err(VolumeError::UnsafeRootComponent);
        }
    }
    Ok(())
}

fn ensure_directory(mode: u32) -> Result<(), VolumeError> {
    if file_type(mode)? == FileType::Directory {
        Ok(())
    } else {
        Err(VolumeError::RootNotDirectory)
    }
}

fn verify_path_still_names_root(
    path: &Path,
    expected: &RootObjectIdentity,
) -> Result<(), VolumeError> {
    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| VolumeError::RootBindingChanged)?;
    let observed = snapshot_root(descriptor.as_fd())?;
    if &observed == expected {
        Ok(())
    } else {
        Err(VolumeError::RootBindingChanged)
    }
}

fn snapshot_root(fd: BorrowedFd<'_>) -> Result<RootObjectIdentity, VolumeError> {
    let stat =
        rustix::fs::fstat(fd).map_err(|error| VolumeError::io("checking the bound root", error))?;
    root_identity_from_stat(&stat)
}

fn root_identity_from_stat(stat: &rustix::fs::Stat) -> Result<RootObjectIdentity, VolumeError> {
    Ok(RootObjectIdentity {
        device: device_to_u64(stat.st_dev)?,
        inode: stat.st_ino,
        generation: stat.st_gen,
        mode: u32::from(stat.st_mode),
        change_time_seconds: stat.st_ctime,
        change_time_nanoseconds: nanoseconds(stat.st_ctime_nsec, "root ctime")?,
    })
}

fn mount_snapshot(fd: BorrowedFd<'_>) -> Result<MountSnapshot, VolumeError> {
    let stat = rustix::fs::fstatfs(fd)
        .map_err(|error| VolumeError::io("reading mounted filesystem metadata", error))?;
    let mount_point = c_char_array(&stat.f_mntonname, "mount point")?;
    let mount_source = c_char_array(&stat.f_mntfromname, "mount source")?;
    let filesystem_type = c_char_array(&stat.f_fstypename, "filesystem type")?;
    let block_size = Some(u64::from(stat.f_bsize));
    let io_size = u64::try_from(stat.f_iosize).ok();
    let block_size_value = u64::from(stat.f_bsize);
    let space = SpaceObservation {
        block_size,
        io_size,
        total_bytes: stat.f_blocks.checked_mul(block_size_value),
        free_bytes: stat.f_bfree.checked_mul(block_size_value),
        available_bytes: stat.f_bavail.checked_mul(block_size_value),
    };
    Ok(MountSnapshot {
        signature: MountSignature {
            filesystem_id: stat.f_fsid,
            mount_point,
            mount_source,
            filesystem_type,
            filesystem_type_number: stat.f_type,
            filesystem_subtype: stat.f_fssubtype,
            flags: stat.f_flags,
            extended_flags: stat.f_flags_ext,
            owner: stat.f_owner,
        },
        space,
    })
}

fn verify_opened_mount_boundary(
    session: &PlatformSession,
    fd: BorrowedFd<'_>,
    observed_device: u64,
) -> Result<(), VolumeError> {
    let observed = mount_snapshot(fd)?;
    if same_mount_boundary(
        session.root_identity.device,
        &session.mount_signature,
        observed_device,
        &observed.signature,
    ) {
        Ok(())
    } else {
        Err(VolumeError::CrossedMountBoundary)
    }
}

fn same_mount_boundary<Fsid: PartialEq>(
    expected_device: u64,
    expected: &MountSignature<Fsid>,
    observed_device: u64,
    observed: &MountSignature<Fsid>,
) -> bool {
    expected_device == observed_device && expected == observed
}

fn c_char_array<const N: usize>(
    input: &[libc::c_char; N],
    field: &'static str,
) -> Result<Vec<u8>, VolumeError> {
    let Some(end) = input.iter().position(|value| *value == 0) else {
        return Err(VolumeError::MalformedSystemMetadata { field });
    };
    Ok(input[..end].iter().map(|value| *value as u8).collect())
}

fn query_native_uuid(fd: BorrowedFd<'_>) -> Result<Option<NativeUuid>, VolumeError> {
    let mut attrs = volume_attrlist(libc::ATTR_VOL_UUID);
    let mut buffer = [0u8; UUID_BUFFER_BYTES];
    call_fgetattrlist(fd, &mut attrs, &mut buffer)?;
    let returned = returned_length(&buffer, "volume UUID")?;
    if matches!(returned, 0 | 4) {
        return Ok(None);
    }
    if returned != UUID_BUFFER_BYTES {
        return Err(VolumeError::MalformedSystemMetadata {
            field: "volume UUID",
        });
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&buffer[4..20]);
    Ok(NativeUuid::from_nonzero(uuid))
}

fn query_format_capabilities(
    fd: BorrowedFd<'_>,
) -> Result<Option<ReadOnlyFormatCapabilities>, VolumeError> {
    let mut attrs = volume_attrlist(libc::ATTR_VOL_CAPABILITIES);
    let mut buffer = [0u8; CAPABILITIES_BUFFER_BYTES];
    call_fgetattrlist(fd, &mut attrs, &mut buffer)?;
    let returned = returned_length(&buffer, "volume capabilities")?;
    if matches!(returned, 0 | 4) {
        return Ok(None);
    }
    if returned != CAPABILITIES_BUFFER_BYTES {
        return Err(VolumeError::MalformedSystemMetadata {
            field: "volume capabilities",
        });
    }
    let values = u32::from_ne_bytes(buffer[4..8].try_into().expect("fixed capability bytes"));
    let valid = u32::from_ne_bytes(buffer[20..24].try_into().expect("fixed valid bytes"));
    Ok(Some(ReadOnlyFormatCapabilities {
        case_sensitive: capability(values, valid, libc::VOL_CAP_FMT_CASE_SENSITIVE),
        case_preserving: capability(values, valid, libc::VOL_CAP_FMT_CASE_PRESERVING),
        persistent_object_ids: capability(values, valid, libc::VOL_CAP_FMT_PERSISTENTOBJECTIDS),
        symbolic_links: capability(values, valid, libc::VOL_CAP_FMT_SYMBOLICLINKS),
        hard_links: capability(values, valid, libc::VOL_CAP_FMT_HARDLINKS),
    }))
}

fn capability(values: u32, valid: u32, mask: u32) -> Option<bool> {
    (valid & mask != 0).then_some(values & mask != 0)
}

fn volume_attrlist(attribute: u32) -> libc::attrlist {
    libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: 0,
        volattr: libc::ATTR_VOL_INFO | attribute,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    }
}

#[allow(unsafe_code)]
fn call_fgetattrlist<const N: usize>(
    fd: BorrowedFd<'_>,
    attrs: &mut libc::attrlist,
    buffer: &mut [u8; N],
) -> Result<(), VolumeError> {
    // SAFETY: `attrs` and `buffer` are valid writable objects for the exact
    // lengths passed to the kernel. The descriptor is borrowed for this call,
    // and no pointer escapes. Buffer contents are length-checked before use.
    let result = unsafe {
        libc::fgetattrlist(
            fd.as_raw_fd(),
            attrs as *mut libc::attrlist as *mut libc::c_void,
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            buffer.len(),
            libc::FSOPT_REPORT_FULLSIZE,
        )
    };
    if result == 0 {
        return Ok(());
    }

    let error = io::Error::last_os_error();
    let optional_unavailable = error.raw_os_error().is_some_and(|code| {
        [libc::EINVAL, libc::ENOTSUP, libc::EPERM, libc::EACCES].contains(&code)
    });
    if optional_unavailable {
        buffer.fill(0);
        Ok(())
    } else {
        Err(VolumeError::io("reading optional volume attributes", error))
    }
}

fn returned_length<const N: usize>(
    buffer: &[u8; N],
    field: &'static str,
) -> Result<usize, VolumeError> {
    let returned = usize::try_from(u32::from_ne_bytes(
        buffer[..4].try_into().expect("length prefix"),
    ))
    .map_err(|_| VolumeError::MalformedSystemMetadata { field })?;
    if returned == 0 {
        return Ok(0);
    }
    if returned > N || returned < 4 {
        Err(VolumeError::MalformedSystemMetadata { field })
    } else {
        Ok(returned)
    }
}

fn nanoseconds(value: libc::c_long, field: &'static str) -> Result<u32, VolumeError> {
    let value = u32::try_from(value).map_err(|_| VolumeError::MalformedSystemMetadata { field })?;
    if value < 1_000_000_000 {
        Ok(value)
    } else {
        Err(VolumeError::MalformedSystemMetadata { field })
    }
}

fn file_type(mode: u32) -> Result<FileType, VolumeError> {
    let mode = u16::try_from(mode)
        .map_err(|_| VolumeError::MalformedSystemMetadata { field: "file mode" })?;
    Ok(FileType::from_raw_mode(mode))
}

fn device_to_u64(value: libc::dev_t) -> Result<u64, VolumeError> {
    u64::try_from(value).map_err(|_| VolumeError::MalformedSystemMetadata {
        field: "device identifier",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_mount(filesystem_id: u64) -> MountSignature<u64> {
        MountSignature {
            filesystem_id,
            mount_point: b"/Volumes/Photos".to_vec(),
            mount_source: b"/dev/disk9s1".to_vec(),
            filesystem_type: b"apfs".to_vec(),
            filesystem_type_number: 24,
            filesystem_subtype: 1,
            flags: 0x1000,
            extended_flags: 0x2000,
            owner: 501,
        }
    }

    #[test]
    fn full_mount_signature_and_device_must_match() {
        let expected = synthetic_mount(7);
        assert!(same_mount_boundary(42, &expected, 42, &expected));
        assert!(!same_mount_boundary(42, &expected, 43, &expected));
    }

    #[test]
    fn same_device_with_different_fsid_is_a_boundary() {
        let expected = synthetic_mount(7);
        let observed = synthetic_mount(8);
        assert!(!same_mount_boundary(42, &expected, 42, &observed));
    }

    #[test]
    fn changed_mountpoint_is_a_boundary() {
        let expected = synthetic_mount(7);
        let mut observed = expected.clone();
        observed.mount_point = b"/Volumes/Replacement".to_vec();
        assert!(!same_mount_boundary(42, &expected, 42, &observed));
    }

    #[test]
    fn changed_subtype_or_extended_flags_is_a_boundary() {
        let expected = synthetic_mount(7);
        let mut changed_subtype = expected.clone();
        changed_subtype.filesystem_subtype ^= 1;
        assert!(!same_mount_boundary(42, &expected, 42, &changed_subtype));

        let mut changed_extended_flags = expected.clone();
        changed_extended_flags.extended_flags ^= 1;
        assert!(!same_mount_boundary(
            42,
            &expected,
            42,
            &changed_extended_flags
        ));
    }

    #[test]
    fn changed_numeric_filesystem_type_or_owner_is_a_boundary() {
        let expected = synthetic_mount(7);
        let mut changed_type = expected.clone();
        changed_type.filesystem_type_number ^= 1;
        assert!(!same_mount_boundary(42, &expected, 42, &changed_type));

        let mut changed_owner = expected.clone();
        changed_owner.owner += 1;
        assert!(!same_mount_boundary(42, &expected, 42, &changed_owner));
    }

    #[test]
    fn all_zero_native_uuid_is_treated_as_unavailable() {
        assert_eq!(NativeUuid::from_nonzero([0; 16]), None);
        assert!(NativeUuid::from_nonzero([1; 16]).is_some());
    }

    #[test]
    fn kernel_length_prefix_is_strictly_bounded() {
        let empty = [0u8; 20];
        assert_eq!(returned_length(&empty, "test").unwrap(), 0);

        let mut exact = [0u8; 20];
        exact[..4].copy_from_slice(&20u32.to_ne_bytes());
        assert_eq!(returned_length(&exact, "test").unwrap(), 20);

        let mut too_small = [0u8; 20];
        too_small[..4].copy_from_slice(&1u32.to_ne_bytes());
        assert!(matches!(
            returned_length(&too_small, "test"),
            Err(VolumeError::MalformedSystemMetadata { .. })
        ));

        let mut too_large = [0u8; 20];
        too_large[..4].copy_from_slice(&21u32.to_ne_bytes());
        assert!(matches!(
            returned_length(&too_large, "test"),
            Err(VolumeError::MalformedSystemMetadata { .. })
        ));
    }

    #[test]
    fn fixed_system_fields_require_terminators_and_valid_nanoseconds() {
        assert!(matches!(
            c_char_array(&[1 as libc::c_char; 4], "test"),
            Err(VolumeError::MalformedSystemMetadata { .. })
        ));
        assert_eq!(nanoseconds(999_999_999, "test").unwrap(), 999_999_999);
        assert!(matches!(
            nanoseconds(1_000_000_000, "test"),
            Err(VolumeError::MalformedSystemMetadata { .. })
        ));
        assert!(matches!(
            nanoseconds(-1, "test"),
            Err(VolumeError::MalformedSystemMetadata { .. })
        ));
    }
}
