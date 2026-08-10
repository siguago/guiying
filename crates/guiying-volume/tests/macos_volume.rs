#![cfg(target_os = "macos")]

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::symlink;

use guiying_volume::{
    BoundVolumeSession, IdentityStrength, KeyDigest, LosslessRelativePath, NativePathEncoding,
    PathError, PathSemanticsProfile, VolumeError, MAX_ROOT_PATH_BYTES,
};
use tempfile::TempDir;

fn relative(session: &BoundVolumeSession, value: &[u8]) -> LosslessRelativePath {
    LosslessRelativePath::from_raw(
        value.to_vec(),
        NativePathEncoding::UnixBytes,
        session.path_semantics(),
    )
    .expect("valid fixture path")
}

#[test]
fn observation_is_read_only_and_every_binding_has_a_new_session() {
    let fixture = TempDir::new().expect("temporary volume root");
    let first = BoundVolumeSession::bind(fixture.path()).expect("first binding");
    let second = BoundVolumeSession::bind(fixture.path()).expect("second binding");

    first.revalidate().expect("bound root remains stable");
    assert_eq!(
        first.observation().identity().key(),
        second.observation().identity().key()
    );
    assert_ne!(
        first.observation().mount_session_key(),
        second.observation().mount_session_key()
    );
    assert_ne!(
        first.path_semantics().profile_key(),
        second.path_semantics().profile_key()
    );
    assert_eq!(first.path_semantics().version(), 1);
    assert_eq!(
        first.path_semantics().encoding(),
        NativePathEncoding::UnixBytes
    );

    let observation = first.observation();
    assert!(!observation
        .mount()
        .mount_point()
        .decode_raw()
        .unwrap()
        .is_empty());
    assert!(!observation
        .mount()
        .mount_source()
        .decode_raw()
        .unwrap()
        .is_empty());
    assert!(!observation
        .mount()
        .filesystem_type()
        .decode_raw()
        .unwrap()
        .is_empty());
    match observation.identity().native_uuid() {
        Some(_) => assert_eq!(observation.identity().strength(), IdentityStrength::Strong),
        None => assert_eq!(observation.identity().strength(), IdentityStrength::Weak),
    }

    let writes = observation.write_capabilities();
    assert_eq!(writes.create(), None);
    assert_eq!(writes.no_replace_create(), None);
    assert_eq!(writes.same_volume_rename(), None);
    assert_eq!(writes.file_fsync(), None);
    assert_eq!(writes.parent_directory_fsync(), None);
    assert_eq!(writes.birthtime_write(), None);
    assert_eq!(writes.mtime_write(), None);

    let json = serde_json::to_value(observation).expect("serialize volume observation for IPC");
    assert!(json["root_identity"]["device"].is_string());
    assert!(json["root_identity"]["inode"].is_string());
    assert!(json["mount"]["raw_flags"].is_string());
    assert!(json["mount"]["space"]["block_size"].is_string());
}

#[test]
fn root_argument_rejects_symlinks_ambiguity_and_non_directories() {
    let fixture = TempDir::new().expect("temporary volume root");
    let real = fixture.path().join("real");
    fs::create_dir(&real).expect("real directory");
    let alias = fixture.path().join("alias");
    symlink(&real, &alias).expect("root symlink");

    assert!(matches!(
        BoundVolumeSession::bind(&alias),
        Err(VolumeError::RootSymlink)
    ));
    let trailing = real.as_os_str().to_owned().into_string().unwrap() + "/";
    assert!(matches!(
        BoundVolumeSession::bind(trailing),
        Err(VolumeError::RootHasEmptyComponent)
    ));
    assert!(matches!(
        BoundVolumeSession::bind(real.join(".")),
        Err(VolumeError::UnsafeRootComponent)
    ));
    assert!(matches!(
        BoundVolumeSession::bind("relative"),
        Err(VolumeError::RootNotAbsolute)
    ));
    let overlong = format!("/{}", "a".repeat(MAX_ROOT_PATH_BYTES));
    assert!(matches!(
        BoundVolumeSession::bind(overlong),
        Err(VolumeError::RootPathTooLong { .. })
    ));

    let regular = fixture.path().join("not-a-directory");
    fs::write(&regular, b"content").expect("regular file");
    assert!(matches!(
        BoundVolumeSession::bind(regular),
        Err(VolumeError::RootNotDirectory)
    ));
}

#[test]
fn relative_open_never_follows_symlinks_and_requires_its_profile() {
    let fixture = TempDir::new().expect("temporary volume root");
    let subdirectory = fixture.path().join("sub");
    fs::create_dir(&subdirectory).expect("subdirectory");
    fs::write(subdirectory.join("photo.jpg"), b"photo bytes").expect("photo");
    symlink(
        subdirectory.join("photo.jpg"),
        fixture.path().join("final-link"),
    )
    .expect("final symlink");
    symlink(&subdirectory, fixture.path().join("directory-link")).expect("directory symlink");

    let session = BoundVolumeSession::bind(fixture.path()).expect("binding");
    let path = relative(&session, b"sub/photo.jpg");
    let mut opened = session.open_regular_file(&path).expect("safe open");
    let mut content = Vec::new();
    opened.read_to_end(&mut content).expect("read photo");
    assert_eq!(content, b"photo bytes");
    assert!(opened
        .verify_unchanged(&session, &path)
        .expect("complete stable-input verification"));

    for unsafe_path in [
        b"final-link".as_slice(),
        b"directory-link/photo.jpg".as_slice(),
    ] {
        let error = match session.open_regular_file(&relative(&session, unsafe_path)) {
            Ok(_) => panic!("symlink must not be followed"),
            Err(error) => error,
        };
        assert!(matches!(error, VolumeError::UnsafePathResolution { .. }));
    }

    let second = BoundVolumeSession::bind(fixture.path()).expect("independent binding");
    let wrong_profile = relative(&second, b"sub/photo.jpg");
    assert!(matches!(
        session.open_regular_file(&wrong_profile),
        Err(VolumeError::Path(PathError::ProfileMismatch))
    ));
    let offline_profile = PathSemanticsProfile::conservative_offline(
        NativePathEncoding::UnixBytes,
        KeyDigest::from_bytes([0x99; 32]),
    );
    let offline_path = LosslessRelativePath::from_raw(
        b"sub/photo.jpg".to_vec(),
        NativePathEncoding::UnixBytes,
        &offline_profile,
    )
    .expect("valid offline path");
    assert!(matches!(
        session.open_regular_file(&offline_path),
        Err(VolumeError::Path(PathError::ProfileMismatch))
    ));
    let root = relative(&session, b"");
    assert!(matches!(
        session.open_regular_file(&root),
        Err(VolumeError::Path(PathError::RootIsNotAFile))
    ));
    assert!(matches!(
        session.open_regular_file(&relative(&session, b"sub")),
        Err(VolumeError::NotRegularFile)
    ));
}

#[test]
fn nested_file_on_the_same_mount_passes_every_descriptor_boundary_check() {
    let fixture = TempDir::new().expect("temporary volume root");
    let nested = fixture.path().join("one").join("two").join("three");
    fs::create_dir_all(&nested).expect("nested directories");
    fs::write(nested.join("photo.jpg"), b"same mount").expect("photo");

    let session = BoundVolumeSession::bind(fixture.path()).expect("binding");
    let path = relative(&session, b"one/two/three/photo.jpg");
    let mut opened = session
        .open_regular_file(&path)
        .expect("all directory and file mount signatures match");
    let mut content = String::new();
    opened.read_to_string(&mut content).expect("read photo");
    assert_eq!(content, "same mount");
    assert!(opened
        .verify_unchanged(&session, &path)
        .expect("stable path on same mount"));
}

#[test]
fn stable_input_verification_detects_mutation_and_path_replacement() {
    let fixture = TempDir::new().expect("temporary volume root");
    let subdirectory = fixture.path().join("sub");
    fs::create_dir(&subdirectory).expect("subdirectory");
    let target = subdirectory.join("photo.jpg");
    fs::write(&target, b"original").expect("photo");

    let session = BoundVolumeSession::bind(fixture.path()).expect("binding");
    let path = relative(&session, b"sub/photo.jpg");
    let opened = session.open_regular_file(&path).expect("safe open");
    OpenOptions::new()
        .append(true)
        .open(&target)
        .expect("open fixture for mutation")
        .write_all(b" changed")
        .expect("mutate fixture");
    assert!(!opened
        .verify_unchanged(&session, &path)
        .expect("mutation is a normal unstable result"));

    fs::write(&target, b"replacement baseline").expect("reset photo");
    let replacement_open = session.open_regular_file(&path).expect("second safe open");
    let moved = subdirectory.join("moved.jpg");
    fs::rename(&target, moved).expect("move original entry");
    fs::write(&target, b"replacement baseline").expect("replace path with same bytes");
    assert!(!replacement_open
        .verify_unchanged(&session, &path)
        .expect("replacement is a normal unstable result"));
}

#[test]
fn opened_files_are_bound_to_both_session_and_path() {
    let fixture = TempDir::new().expect("temporary volume root");
    fs::write(fixture.path().join("one.jpg"), b"one").expect("first photo");
    fs::write(fixture.path().join("two.jpg"), b"two").expect("second photo");
    let first = BoundVolumeSession::bind(fixture.path()).expect("first binding");
    let second = BoundVolumeSession::bind(fixture.path()).expect("second binding");
    let one = relative(&first, b"one.jpg");
    let two = relative(&first, b"two.jpg");
    let opened = first.open_regular_file(&one).expect("safe open");

    assert!(matches!(
        opened.verify_unchanged(&second, &relative(&second, b"one.jpg")),
        Err(VolumeError::FileSessionMismatch)
    ));
    assert!(matches!(
        opened.verify_unchanged(&first, &two),
        Err(VolumeError::FilePathMismatch)
    ));
}

#[test]
fn replacing_the_selected_root_invalidates_the_binding() {
    let fixture = TempDir::new().expect("temporary parent");
    let selected = fixture.path().join("selected");
    fs::create_dir(&selected).expect("selected root");
    let session = BoundVolumeSession::bind(&selected).expect("binding");

    let old = fixture.path().join("old-selected");
    fs::rename(&selected, old).expect("move selected root");
    fs::create_dir(&selected).expect("same-name replacement root");
    assert!(matches!(
        session.revalidate(),
        Err(VolumeError::RootBindingChanged)
    ));
}
