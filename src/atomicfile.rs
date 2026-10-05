//! Crash-safe replacement of the small state files sofka rewrites.
//!
//! Sort, namespace, and fleet choices are rewritten whole every time one
//! changes. Writing them in place is not safe: `File::create` truncates the
//! target before the new bytes land, so a crash, a power loss, or a second
//! sofka writing the same file can leave a half-written mix that `load()`
//! then silently discards as unparsable — the user's remembered choices gone
//! because the process died at the wrong microsecond. Renaming a finished
//! temp file over the target has no such window.

use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Separates concurrent writes from this process; see [`temp_path`].
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// How many names one write may try before giving up. A collision means
/// another writer holds that exact name right now, which the next candidate
/// escapes; the bound is here so a directory that refuses every create fails
/// fast instead of spinning.
const TEMP_ATTEMPTS: u32 = 16;

/// Write `contents` to `path` as one indivisible replacement, creating the
/// parent directory if it is missing.
///
/// The bytes go to a sibling temp file that is flushed and then renamed over
/// the target. `rename` replaces atomically, so every reader — another sofka,
/// a `cat`, this process on its next launch — sees either the whole previous
/// file or the whole new one, never a tear.
pub fn write(path: &Path, contents: &str) -> Result<(), String> {
    write_with(path, contents, temp_path)
}

/// Replace an existing file that may hold secrets, such as a kubeconfig, in
/// one step. A symlink stays a symlink: the file it points to is replaced.
/// The replacement takes that file's permissions and, on Unix, its owner and
/// group, and on Linux its extended attributes, such as an ACL or a security
/// label, before any byte is written. The file is untouched when a new one
/// cannot carry all of that: `PermissionDenied` for a file someone else owns,
/// `Unsupported` for attributes it cannot copy, and on systems where it
/// cannot see them.
pub fn replace(path: &Path, contents: &str) -> std::io::Result<()> {
    if !cfg!(target_os = "linux") {
        return Err(std::io::ErrorKind::Unsupported.into());
    }
    let target = std::fs::canonicalize(path)?;
    let meta = std::fs::metadata(&target)?;
    let (file, temp) = create_temp(&target, &mut temp_path)?;
    let replaced = keep_metadata(&file, &target, &meta)
        .and_then(|()| write_then_rename(file, &temp, &target, contents));
    if replaced.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    replaced
}

/// Copy every extended attribute of `from`, such as its ACL and security
/// label, to `to`.
#[cfg(target_os = "linux")]
fn copy_extended_attributes(from: &Path, to: &std::fs::File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;

    let path = std::ffi::CString::new(from.as_os_str().as_bytes())?;
    // Ask for a size, then fill a buffer of it. The list can change in
    // between, which the second call reports as an error.
    let read = |fill: &dyn Fn(*mut libc::c_char, usize) -> isize| -> std::io::Result<Vec<u8>> {
        let size = fill(std::ptr::null_mut(), 0);
        let size = usize::try_from(size).map_err(|_| std::io::Error::last_os_error())?;
        let mut buffer = vec![0u8; size];
        let size = fill(buffer.as_mut_ptr().cast(), buffer.len());
        let size = usize::try_from(size).map_err(|_| std::io::Error::last_os_error())?;
        buffer.truncate(size);
        Ok(buffer)
    };
    // SAFETY: `path` is a valid C string and the buffer is `len` bytes.
    let names = match read(&|buffer, len| unsafe { libc::listxattr(path.as_ptr(), buffer, len) }) {
        Ok(names) => names,
        // A file system without extended attributes has none to copy.
        Err(error) if error.raw_os_error() == Some(libc::ENOTSUP) => return Ok(()),
        Err(error) => return Err(error),
    };
    for name in names
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
    {
        let name = std::ffi::CString::new(name)?;
        // SAFETY: valid C strings, and the buffer is `len` bytes.
        let value = read(&|buffer, len| unsafe {
            libc::getxattr(path.as_ptr(), name.as_ptr(), buffer.cast(), len)
        })?;
        // SAFETY: an open descriptor, a valid C string, and `value` as is.
        let set = unsafe {
            libc::fsetxattr(
                to.as_raw_fd(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        };
        if set != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Give the new `file` the mode, owner, group, and extended attributes of
/// `original`.
fn keep_metadata(
    file: &std::fs::File,
    original: &Path,
    meta: &std::fs::Metadata,
) -> std::io::Result<()> {
    file.set_permissions(meta.permissions())?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt as _;
        std::os::unix::fs::fchown(file, Some(meta.uid()), Some(meta.gid()))?;
        copy_extended_attributes(original, file)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::Unsupported, error))?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = original;
    Ok(())
}

/// [`write`], with the temp-name sequence injectable so the collision path can
/// be driven from a test — the real names mix in a clock reading and cannot be
/// predicted from outside.
fn write_with(
    path: &Path,
    contents: &str,
    mut candidate: impl FnMut(&Path) -> PathBuf,
) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let (file, temp) = create_temp(path, &mut candidate).map_err(|e| e.to_string())?;
    write_then_rename(file, &temp, path, contents).map_err(|e| {
        // A failed attempt must not litter the state directory with a
        // `sort.toml.tmp…` nobody will ever clean up. Only ever this
        // process's own temp file: `create_new` below refused every name that
        // already existed, so nothing here can delete a file we did not make.
        let _ = std::fs::remove_file(&temp);
        e.to_string()
    })
}

/// Claim a temp name nobody else holds, and return it already open.
///
/// `create_new` is the whole point: `File::create` would *truncate* a name
/// another writer is using, and pid plus a process-local counter is not enough
/// to rule that out — two sofkas sharing a state directory over NFS, or in
/// separate pid namespaces, can reach the same pid and the same counter. The
/// loser of that race would then write through its still-open handle into an
/// inode the winner had already renamed into place, tearing the published file
/// that the rename exists to keep whole. Refusing an existing name turns that
/// corruption into a retry.
fn create_temp(
    path: &Path,
    candidate: &mut impl FnMut(&Path) -> PathBuf,
) -> std::io::Result<(std::fs::File, PathBuf)> {
    let mut taken = None;
    for _ in 0..TEMP_ATTEMPTS {
        let temp = candidate(path);
        match std::fs::File::options()
            .write(true)
            .create_new(true)
            .open(&temp)
        {
            Ok(file) => return Ok((file, temp)),
            // Somebody else's, mid-write. Not ours to truncate, and not ours
            // to clean up either — take the next name instead.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => taken = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(taken.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "no free temp name beside the state file",
        )
    }))
}

fn write_then_rename(
    mut file: std::fs::File,
    temp: &Path,
    path: &Path,
    contents: &str,
) -> std::io::Result<()> {
    file.write_all(contents.as_bytes())?;
    // Without this the rename can reach disk before the bytes it publishes,
    // so a power loss leaves the target pointing at a zero-filled file —
    // exactly the tear the rename is here to prevent. The directory entry is
    // deliberately left unsynced: if the rename itself is lost, the previous
    // complete file survives, which is a fine outcome for remembered UI state
    // and saves a second flush on every keystroke that changes a sort.
    file.sync_all()?;
    drop(file);
    std::fs::rename(temp, path)
}

/// A sibling of `path` — `rename` is only atomic within one filesystem, so the
/// temp file cannot live in `/tmp`.
///
/// Three things separate this name from another writer's: the pid, the counter
/// that separates writes racing inside this process, and a clock reading for
/// the case the other two match, which across hosts sharing a state directory
/// and across pid namespaces they can. None of the three is a guarantee, which
/// is why [`create_temp`] refuses a name that already exists; this only has to
/// make that retry rare.
fn temp_path(path: &Path) -> PathBuf {
    let n = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let mut name = OsString::from(path.as_os_str());
    name.push(format!(".tmp{}.{n:x}.{nanos:x}", std::process::id()));
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sofka-atomicfile-{}-{tag}-{}",
            std::process::id(),
            NEXT_TEMP.load(Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn creates_missing_parents_and_replaces_in_place() {
        let dir = scratch("replace");
        let path = dir.join("nested").join("sort.toml");
        write(&path, "first").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first");
        write(&path, "second").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "second");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn leaves_no_temp_file_behind() {
        let dir = scratch("cleanup");
        let path = dir.join("sort.toml");
        write(&path, "a").unwrap();
        write(&path, "bb").unwrap();
        let left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, vec![OsString::from("sort.toml")]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_write_keeps_the_old_file_and_cleans_up() {
        let dir = scratch("failure");
        // Renaming a file over a directory fails, which stands in for any
        // mid-write failure: the point is that the target is untouched.
        let good = dir.join("sort.toml");
        write(&good, "kept").unwrap();
        let blocked = dir.join("blocked.toml");
        std::fs::create_dir(&blocked).unwrap();

        assert!(write(&blocked, "never lands").is_err());
        assert_eq!(std::fs::read_to_string(&good).unwrap(), "kept");
        assert!(blocked.is_dir(), "target survives the failed write");
        let mut left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        left.sort();
        assert_eq!(
            left,
            vec![OsString::from("blocked.toml"), OsString::from("sort.toml")]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn temp_paths_are_siblings_and_unique() {
        let path = Path::new("/var/state/sofka/sort.toml");
        let a = temp_path(path);
        let b = temp_path(path);
        assert_ne!(a, b);
        assert_eq!(a.parent(), path.parent());
        assert_eq!(b.parent(), path.parent());
    }

    /// Hands `write` a name another writer already holds. `File::create` used
    /// to truncate that file to zero and publish through the loser's still-open
    /// handle; the write must step over the name instead, leaving the bytes
    /// untouched.
    #[test]
    fn a_colliding_temp_file_is_neither_truncated_nor_removed() {
        let dir = scratch("collision");
        let path = dir.join("sort.toml");
        write(&path, "published").unwrap();

        let theirs = dir.join("sort.toml.tmp-theirs");
        std::fs::write(&theirs, "their in-flight bytes").unwrap();
        let ours = dir.join("sort.toml.tmp-ours");

        let names = [theirs.clone(), ours.clone()];
        let mut handed = 0;
        write_with(&path, "second", |_| {
            let next = names[handed.min(names.len() - 1)].clone();
            handed += 1;
            next
        })
        .unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "second");
        assert_eq!(
            std::fs::read_to_string(&theirs).unwrap(),
            "their in-flight bytes",
            "the other writer's temp file was truncated"
        );
        assert!(!ours.exists(), "our own temp file outlived the rename");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The cleanup after a failed write may only remove the temp file that
    /// write created. It never opened the other writer's, so it must not
    /// delete it on the way out.
    #[test]
    fn a_failed_write_leaves_another_writers_temp_file_alone() {
        let dir = scratch("collision-failure");
        std::fs::create_dir_all(&dir).unwrap();
        // Renaming over a directory fails, so the write claims a temp file and
        // then loses it at the rename — the path that runs the cleanup.
        let blocked = dir.join("blocked.toml");
        std::fs::create_dir(&blocked).unwrap();

        let theirs = dir.join("blocked.toml.tmp-theirs");
        std::fs::write(&theirs, "their in-flight bytes").unwrap();
        let ours = dir.join("blocked.toml.tmp-ours");

        let names = [theirs.clone(), ours.clone()];
        let mut handed = 0;
        assert!(
            write_with(&blocked, "never lands", |_| {
                let next = names[handed.min(names.len() - 1)].clone();
                handed += 1;
                next
            })
            .is_err()
        );

        assert_eq!(
            std::fs::read_to_string(&theirs).unwrap(),
            "their in-flight bytes",
            "cleanup deleted a temp file this write never created"
        );
        assert!(!ours.exists(), "our own temp file was left behind");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn replace_keeps_mode_owner_and_symlink() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let dir = scratch("replace");
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("kubeconfig");
        std::fs::write(&target, "old").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
        let before = std::fs::metadata(&target).unwrap();
        let link = dir.join("config");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        replace(&link, "new").unwrap();

        assert!(std::fs::symlink_metadata(&link).unwrap().is_symlink());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "new");
        let after = std::fs::metadata(&target).unwrap();
        assert_eq!(after.permissions().mode() & 0o777, 0o640);
        assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            2,
            "temp file left behind"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn replace_keeps_extended_attributes() {
        use std::os::unix::ffi::OsStrExt as _;

        let dir = scratch("xattr");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("kubeconfig");
        std::fs::write(&path, "old").unwrap();
        let attribute = |path: &Path| {
            let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            let mut value = [0u8; 8];
            // SAFETY: valid C strings and an 8-byte buffer.
            let len = unsafe {
                libc::getxattr(
                    name.as_ptr(),
                    c"user.sofka-test".as_ptr(),
                    value.as_mut_ptr().cast(),
                    value.len(),
                )
            };
            usize::try_from(len).ok().map(|len| value[..len].to_vec())
        };
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: valid C strings and a 1-byte value buffer.
        let set = unsafe {
            libc::setxattr(
                name.as_ptr(),
                c"user.sofka-test".as_ptr(),
                b"1".as_ptr().cast(),
                1,
                0,
            )
        };
        if set != 0 {
            // The scratch file system takes no user attributes.
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }

        replace(&path, "new").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
        assert_eq!(attribute(&path), Some(b"1".to_vec()));
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            1,
            "temp file left behind"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
