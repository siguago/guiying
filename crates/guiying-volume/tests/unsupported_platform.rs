#![cfg(not(target_os = "macos"))]

use guiying_volume::{BoundVolumeSession, VolumeError};

#[test]
fn volume_binding_fails_closed_on_unsupported_platforms() {
    let root = std::env::current_dir().expect("current directory");
    assert!(matches!(
        BoundVolumeSession::bind(root),
        Err(VolumeError::UnsupportedPlatform { .. })
    ));
}
