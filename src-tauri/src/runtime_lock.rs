use std::fmt;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(windows)]
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;

#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
#[cfg(windows)]
const FILE_SHARE_READ: u32 = 0x0000_0001;
#[cfg(windows)]
const FILE_SHARE_WRITE: u32 = 0x0000_0002;

const RUNTIME_LOCK_FILE_NAME: &str = "guiying.runtime.lock";

#[cfg(test)]
static RUNTIME_LOCK_TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(crate) fn test_serial_guard() -> std::sync::MutexGuard<'static, ()> {
    RUNTIME_LOCK_TEST_SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[derive(Debug)]
pub(crate) enum RuntimeLockError {
    InvalidAppDataDirectory(&'static str),
    AlreadyHeld,
    Io {
        operation: &'static str,
        source: io::Error,
    },
}

impl RuntimeLockError {
    fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }
}

impl fmt::Display for RuntimeLockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAppDataDirectory(reason) => {
                write!(formatter, "应用数据目录不满足安全要求：{reason}")
            }
            Self::AlreadyHeld => write!(
                formatter,
                "另一个归影进程正在使用本地审计数据库；本进程已安全停止初始化。"
            ),
            Self::Io { operation, source } => {
                write!(formatter, "{operation}失败：{source}")
            }
        }
    }
}

impl std::error::Error for RuntimeLockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::InvalidAppDataDirectory(_) | Self::AlreadyHeld => None,
        }
    }
}

/// Process-lifetime authority to initialize or use Guiying's app-private DB.
///
/// Dropping this value releases the OS advisory lock. Tauri stores it as
/// managed application state, so closing the main window cannot accidentally
/// release the lock while the process is still alive.
#[derive(Debug)]
pub(crate) struct AppRuntimeLock {
    file: File,
    lock_path: PathBuf,
    canonical_app_data_dir: PathBuf,
}

impl AppRuntimeLock {
    pub(crate) fn acquire(app_data_dir: &Path) -> Result<Self, RuntimeLockError> {
        let canonical_app_data_dir = prepare_app_data_directory(app_data_dir)?;
        let lock_path = canonical_app_data_dir.join(RUNTIME_LOCK_FILE_NAME);
        let file = open_runtime_lock_file(&lock_path)?;
        validate_runtime_lock_file(&file, &lock_path)?;
        match file.try_lock() {
            Ok(()) => {
                // Revalidate after the OS lock is held. This closes the
                // open/validate/lock replacement window before any Store is
                // allowed to initialize.
                validate_app_data_directory(&canonical_app_data_dir)?;
                validate_runtime_lock_file(&file, &lock_path)?;
                Ok(Self {
                    file,
                    lock_path,
                    canonical_app_data_dir,
                })
            }
            Err(TryLockError::WouldBlock) => Err(RuntimeLockError::AlreadyHeld),
            Err(TryLockError::Error(source)) => {
                Err(RuntimeLockError::io("取得应用进程独占锁", source))
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn path(&self) -> &Path {
        &self.lock_path
    }

    pub(crate) fn canonical_app_data_dir(&self) -> &Path {
        &self.canonical_app_data_dir
    }

    pub(crate) fn verify_integrity(&self) -> Result<(), RuntimeLockError> {
        validate_app_data_directory(&self.canonical_app_data_dir)?;
        validate_runtime_lock_file(&self.file, &self.lock_path)
    }
}

fn prepare_app_data_directory(path: &Path) -> Result<PathBuf, RuntimeLockError> {
    if !path.is_absolute() {
        return Err(RuntimeLockError::InvalidAppDataDirectory(
            "路径必须为绝对路径",
        ));
    }

    #[cfg(unix)]
    {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder
            .create(path)
            .map_err(|source| RuntimeLockError::io("创建应用数据目录", source))?;
    }
    #[cfg(not(unix))]
    fs::create_dir_all(path).map_err(|source| RuntimeLockError::io("创建应用数据目录", source))?;

    #[cfg(unix)]
    {
        let metadata = fs::symlink_metadata(path)
            .map_err(|source| RuntimeLockError::io("检查应用数据目录", source))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(RuntimeLockError::InvalidAppDataDirectory(
                "目录不能是符号链接、重解析点或非目录对象",
            ));
        }
        // SAFETY: geteuid has no preconditions and does not dereference memory.
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.uid() != effective_uid {
            return Err(RuntimeLockError::InvalidAppDataDirectory(
                "目录所有者不是当前有效用户",
            ));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|source| RuntimeLockError::io("收紧应用数据目录权限", source))?;
        }
    }

    validate_app_data_directory(path)?;
    let canonical = fs::canonicalize(path)
        .map_err(|source| RuntimeLockError::io("解析应用数据目录", source))?;
    validate_app_data_directory(&canonical)?;
    Ok(canonical)
}

fn validate_app_data_directory(path: &Path) -> Result<(), RuntimeLockError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| RuntimeLockError::io("检查应用数据目录", source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RuntimeLockError::InvalidAppDataDirectory(
            "目录不能是符号链接、重解析点或非目录对象",
        ));
    }

    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions and does not dereference memory.
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.uid() != effective_uid {
            return Err(RuntimeLockError::InvalidAppDataDirectory(
                "目录所有者不是当前有效用户",
            ));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(RuntimeLockError::InvalidAppDataDirectory(
                "目录权限必须限制为当前用户可访问（0700或更严格）",
            ));
        }
    }
    #[cfg(windows)]
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(RuntimeLockError::InvalidAppDataDirectory(
            "目录不能是Windows重解析点",
        ));
    }
    Ok(())
}

fn open_runtime_lock_file(path: &Path) -> Result<File, RuntimeLockError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    #[cfg(windows)]
    options
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    match options.open(path) {
        Ok(file) => Ok(file),
        #[cfg(unix)]
        Err(source) if source.raw_os_error() == Some(libc::ELOOP) => Err(
            RuntimeLockError::InvalidAppDataDirectory("进程锁不能是符号链接"),
        ),
        Err(source) => Err(RuntimeLockError::io("打开应用进程锁", source)),
    }
}

fn validate_runtime_lock_file(file: &File, path: &Path) -> Result<(), RuntimeLockError> {
    let handle_metadata = file
        .metadata()
        .map_err(|source| RuntimeLockError::io("检查应用进程锁句柄", source))?;
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|source| RuntimeLockError::io("检查应用进程锁路径", source))?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || !handle_metadata.is_file()
    {
        return Err(RuntimeLockError::InvalidAppDataDirectory(
            "进程锁必须是普通文件且不能是符号链接",
        ));
    }

    #[cfg(unix)]
    {
        if handle_metadata.dev() != path_metadata.dev()
            || handle_metadata.ino() != path_metadata.ino()
        {
            return Err(RuntimeLockError::InvalidAppDataDirectory(
                "进程锁路径在打开期间发生替换",
            ));
        }
        // SAFETY: geteuid has no preconditions and does not dereference memory.
        let effective_uid = unsafe { libc::geteuid() };
        if handle_metadata.uid() != effective_uid || path_metadata.uid() != effective_uid {
            return Err(RuntimeLockError::InvalidAppDataDirectory(
                "进程锁所有者不是当前有效用户",
            ));
        }
        if handle_metadata.nlink() != 1 || path_metadata.nlink() != 1 {
            return Err(RuntimeLockError::InvalidAppDataDirectory(
                "进程锁不能存在硬链接别名",
            ));
        }
        if handle_metadata.permissions().mode() & 0o077 != 0 {
            return Err(RuntimeLockError::InvalidAppDataDirectory(
                "进程锁不能向组或其他用户开放",
            ));
        }
    }

    #[cfg(windows)]
    {
        if handle_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || path_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(RuntimeLockError::InvalidAppDataDirectory(
                "进程锁不能是Windows重解析点",
            ));
        }
        // The by-handle identity accessors on std's Windows Metadata are still
        // unstable, so read the same fields through GetFileInformationByHandle.
        // The path side needs its own handle: only a handle can report volume
        // serial, file index, and link count on stable.
        let handle_identity = read_windows_lock_identity(file, "检查应用进程锁句柄")?;
        let path_handle = open_runtime_lock_path_identity_handle(path)?;
        let path_identity = read_windows_lock_identity(&path_handle, "检查应用进程锁路径")?;
        if handle_identity.volume_serial != path_identity.volume_serial
            || handle_identity.file_index != path_identity.file_index
        {
            return Err(RuntimeLockError::InvalidAppDataDirectory(
                "进程锁路径在打开期间发生替换",
            ));
        }
        if handle_identity.number_of_links != 1 || path_identity.number_of_links != 1 {
            return Err(RuntimeLockError::InvalidAppDataDirectory(
                "进程锁不能存在硬链接别名",
            ));
        }
    }

    Ok(())
}

/// Identity fields Windows only exposes through an open handle.
#[cfg(windows)]
struct WindowsLockIdentity {
    volume_serial: u32,
    file_index: u64,
    number_of_links: u32,
}

#[cfg(windows)]
fn open_runtime_lock_path_identity_handle(path: &Path) -> Result<File, RuntimeLockError> {
    // Reparse points stay unfollowed here for the same reason the lock itself
    // is opened that way: a swapped path must be reported, not silently
    // resolved to whatever it now points at.
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|source| RuntimeLockError::io("检查应用进程锁路径", source))
}

#[cfg(windows)]
fn read_windows_lock_identity(
    handle: &File,
    operation: &'static str,
) -> Result<WindowsLockIdentity, RuntimeLockError> {
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let mut information = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    // SAFETY: the handle outlives the call and the OS fully initializes the
    // structure whenever it reports success.
    let succeeded = unsafe {
        GetFileInformationByHandle(handle.as_raw_handle().cast(), information.as_mut_ptr())
    };
    if succeeded == 0 {
        return Err(RuntimeLockError::io(operation, io::Error::last_os_error()));
    }
    // SAFETY: the call above reported success, so the structure is initialized.
    let information = unsafe { information.assume_init() };
    Ok(WindowsLockIdentity {
        volume_serial: information.dwVolumeSerialNumber,
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
        number_of_links: information.nNumberOfLinks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    const CHILD_LOCK_PATH_ENV: &str = "GUIYING_TEST_RUNTIME_LOCK_DIRECTORY";
    const CHILD_CRASH_LOCK_PATH_ENV: &str = "GUIYING_TEST_RUNTIME_LOCK_CRASH_DIRECTORY";

    #[test]
    fn second_handle_in_the_same_process_is_rejected() {
        let _serial = test_serial_guard();
        let directory = tempfile::tempdir().expect("runtime lock fixture");
        let first = AppRuntimeLock::acquire(directory.path()).expect("first runtime lock");
        assert!(first.path().is_file());
        assert!(matches!(
            AppRuntimeLock::acquire(directory.path()),
            Err(RuntimeLockError::AlreadyHeld)
        ));
        drop(first);
        AppRuntimeLock::acquire(directory.path())
            .expect("lock should release on process-state drop");
    }

    #[test]
    fn another_process_cannot_acquire_the_runtime_lock() {
        let _serial = test_serial_guard();
        let directory = tempfile::tempdir().expect("runtime lock fixture");
        let _lock = AppRuntimeLock::acquire(directory.path()).expect("parent runtime lock");
        let output = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg("runtime_lock::tests::child_observes_held_runtime_lock")
            .arg("--nocapture")
            .env(CHILD_LOCK_PATH_ENV, directory.path())
            .output()
            .expect("runtime lock child process");
        assert!(
            output.status.success(),
            "child lock probe failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn child_observes_held_runtime_lock() {
        let _serial = test_serial_guard();
        let Some(directory) = std::env::var_os(CHILD_LOCK_PATH_ENV) else {
            return;
        };
        assert!(matches!(
            AppRuntimeLock::acquire(Path::new(&directory)),
            Err(RuntimeLockError::AlreadyHeld)
        ));
    }

    #[test]
    fn process_crash_releases_the_runtime_lock() {
        let _serial = test_serial_guard();
        let directory = tempfile::tempdir().expect("runtime lock fixture");
        let output = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg("runtime_lock::tests::child_crashes_while_holding_runtime_lock")
            .arg("--nocapture")
            .env(CHILD_CRASH_LOCK_PATH_ENV, directory.path())
            .output()
            .expect("runtime lock crash child process");
        assert!(
            !output.status.success(),
            "crash probe must terminate abnormally"
        );
        AppRuntimeLock::acquire(directory.path())
            .expect("OS must release the process lock after a crash");
    }

    #[test]
    fn child_crashes_while_holding_runtime_lock() {
        let _serial = test_serial_guard();
        let Some(directory) = std::env::var_os(CHILD_CRASH_LOCK_PATH_ENV) else {
            return;
        };
        let _lock = AppRuntimeLock::acquire(Path::new(&directory))
            .expect("crash child should acquire runtime lock");
        std::process::abort();
    }

    #[test]
    fn lock_rejects_relative_directories_and_symlink_files() {
        let _serial = test_serial_guard();
        assert!(matches!(
            AppRuntimeLock::acquire(Path::new("relative-app-data")),
            Err(RuntimeLockError::InvalidAppDataDirectory(_))
        ));

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let directory = tempfile::tempdir().expect("runtime lock fixture");
            let target = directory.path().join("target");
            File::create(&target).expect("lock symlink target");
            symlink(&target, directory.path().join(RUNTIME_LOCK_FILE_NAME))
                .expect("lock symlink fixture");
            assert!(matches!(
                AppRuntimeLock::acquire(directory.path()),
                Err(RuntimeLockError::InvalidAppDataDirectory(_))
            ));

            let parent = tempfile::tempdir().expect("app data symlink fixture");
            let real_directory = parent.path().join("real");
            fs::create_dir(&real_directory).expect("real app data directory");
            fs::set_permissions(&real_directory, fs::Permissions::from_mode(0o700))
                .expect("secure app data permissions");
            let linked_directory = parent.path().join("linked");
            symlink(&real_directory, &linked_directory).expect("app data directory symlink");
            assert!(matches!(
                AppRuntimeLock::acquire(&linked_directory),
                Err(RuntimeLockError::InvalidAppDataDirectory(_))
            ));
        }
    }

    #[test]
    fn window_scoped_cleanup_cannot_release_a_live_application_lock() {
        let _serial = test_serial_guard();
        let directory = tempfile::tempdir().expect("runtime lock fixture");
        let application_lock =
            AppRuntimeLock::acquire(directory.path()).expect("application runtime lock");

        // A window close callback owns no reference to the managed lock. Its
        // scoped state can be discarded while the application lock remains.
        let window_scoped_state = String::from("main");
        drop(window_scoped_state);
        let output = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg("runtime_lock::tests::child_observes_held_runtime_lock")
            .arg("--nocapture")
            .env(CHILD_LOCK_PATH_ENV, directory.path())
            .output()
            .expect("window-close child lock probe");
        assert!(output.status.success(), "application lock must remain held");
        drop(application_lock);
        AppRuntimeLock::acquire(directory.path())
            .expect("application shutdown should release the runtime lock");
    }

    #[cfg(unix)]
    #[test]
    fn locked_path_replacement_is_detected_before_store_initialization() {
        let _serial = test_serial_guard();
        let directory = tempfile::tempdir().expect("runtime lock fixture");
        let application_lock =
            AppRuntimeLock::acquire(directory.path()).expect("application runtime lock");
        let displaced = directory.path().join("displaced.runtime.lock");
        fs::rename(application_lock.path(), &displaced).expect("move locked inode aside");
        let replacement = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(application_lock.path())
            .expect("replacement lock path");
        drop(replacement);
        assert!(matches!(
            application_lock.verify_integrity(),
            Err(RuntimeLockError::InvalidAppDataDirectory(_))
        ));
    }
}
