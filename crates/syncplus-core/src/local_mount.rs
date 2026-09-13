use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::mpsc,
    thread,
    time::Duration,
};

use crate::volume::io_error_means_unavailable;

const AVAILABILITY_STAT_TIMEOUT: Duration = Duration::from_secs(2);

/// Common Linux mount prefixes for removable or external volumes.
pub(crate) fn remount_prefix(path: &Path) -> Option<&'static Path> {
    if path.starts_with("/run/media") {
        Some(Path::new("/run/media"))
    } else if path.starts_with("/media") {
        Some(Path::new("/media"))
    } else if path.starts_with("/mnt") {
        Some(Path::new("/mnt"))
    } else {
        None
    }
}

/// Whether a path under `/mnt`, `/media`, or `/run/media` has a dedicated mount.
///
/// `None` means the path is not under those prefixes. `Some(false)` means the
/// drive is not mounted, so `stat` must not be used (it can hang for a minute).
pub(crate) fn dedicated_mount_covers(path: &Path, mounts: &[PathBuf]) -> Option<bool> {
    let prefix = remount_prefix(path)?;
    let covering = mounts
        .iter()
        .filter(|mount| path.starts_with(mount))
        .max_by_key(|mount| mount.as_os_str().len());
    Some(
        covering
            .map(|mount| mount.starts_with(prefix))
            .unwrap_or(false),
    )
}

pub(crate) fn read_mount_points() -> Vec<PathBuf> {
    read_mountinfo_points()
        .or_else(read_proc_mounts_points)
        .unwrap_or_default()
}

fn read_mountinfo_points() -> Option<Vec<PathBuf>> {
    let body = fs::read_to_string("/proc/self/mountinfo").ok()?;
    Some(parse_mountinfo_points(&body))
}

fn read_proc_mounts_points() -> Option<Vec<PathBuf>> {
    let body = fs::read_to_string("/proc/mounts").ok()?;
    Some(parse_proc_mounts_points(&body))
}

fn parse_mountinfo_points(body: &str) -> Vec<PathBuf> {
    body.lines()
        .filter_map(|line| {
            let mount = line.split_whitespace().nth(4)?;
            Some(PathBuf::from(unescape_mount(mount)))
        })
        .collect()
}

fn parse_proc_mounts_points(body: &str) -> Vec<PathBuf> {
    body.lines()
        .filter_map(|line| {
            let mount = line.split_whitespace().nth(1)?;
            Some(PathBuf::from(unescape_mount(mount)))
        })
        .collect()
}

fn unescape_mount(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            let mut octal = String::new();
            for _ in 0..3 {
                match chars.peek() {
                    Some(digit) if digit.is_ascii_digit() => {
                        octal.push(*digit);
                        chars.next();
                    }
                    _ => break,
                }
            }
            if let Ok(code) = u8::from_str_radix(&octal, 8) {
                out.push(char::from(code));
            } else {
                out.push('\\');
                out.push_str(&octal);
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// True when the path is a present local directory. Unmounted `/mnt` peers
/// return false without waiting on a kernel `stat` timeout.
pub(crate) fn local_directory_present(path: &Path) -> bool {
    if dedicated_mount_covers(path, &read_mount_points()) == Some(false) {
        return false;
    }
    match metadata_within(path, AVAILABILITY_STAT_TIMEOUT) {
        Ok(Ok(metadata)) => metadata.is_dir(),
        Ok(Err(error)) if io_error_means_unavailable(&error) => false,
        Ok(Err(_)) => false,
        Err(_) => false,
    }
}

fn metadata_within(
    path: &Path,
    timeout: Duration,
) -> Result<io::Result<fs::Metadata>, mpsc::RecvTimeoutError> {
    let path = path.to_path_buf();
    let fallback = path.clone();
    let (sender, receiver) = mpsc::channel();
    let spawn = thread::Builder::new()
        .name("syncplus-path-stat".to_owned())
        .spawn(move || {
            let _ = sender.send(fs::symlink_metadata(&path));
        });
    if spawn.is_err() {
        return Ok(fs::symlink_metadata(fallback));
    }
    receiver.recv_timeout(timeout)
}

#[cfg(test)]
mod tests {
    use super::{
        dedicated_mount_covers, parse_mountinfo_points, parse_proc_mounts_points, remount_prefix,
        unescape_mount,
    };
    use std::path::{Path, PathBuf};

    #[test]
    fn remount_prefixes_match_common_linux_mount_roots() {
        assert_eq!(
            remount_prefix(Path::new("/mnt/elements/Charts")),
            Some(Path::new("/mnt"))
        );
        assert_eq!(
            remount_prefix(Path::new("/media/curryman/USB")),
            Some(Path::new("/media"))
        );
        assert_eq!(
            remount_prefix(Path::new("/run/media/curryman/SD/data")),
            Some(Path::new("/run/media"))
        );
        assert_eq!(remount_prefix(Path::new("/home/curryman/Charts")), None);
    }

    #[test]
    fn unmounted_mnt_paths_are_detected_from_the_mount_table_without_stat() {
        let mounts = [
            PathBuf::from("/"),
            PathBuf::from("/home"),
            PathBuf::from("/boot"),
        ];
        assert_eq!(
            dedicated_mount_covers(Path::new("/mnt/elements/Charts"), &mounts),
            Some(false)
        );
        assert_eq!(
            dedicated_mount_covers(Path::new("/home/curryman/Charts"), &mounts),
            None
        );
    }

    #[test]
    fn a_mounted_elements_volume_covers_its_charts_folder() {
        let mounts = [
            PathBuf::from("/"),
            PathBuf::from("/home"),
            PathBuf::from("/mnt/elements"),
        ];
        assert_eq!(
            dedicated_mount_covers(Path::new("/mnt/elements/Charts"), &mounts),
            Some(true)
        );
        assert_eq!(
            dedicated_mount_covers(Path::new("/mnt/other/Charts"), &mounts),
            Some(false)
        );
    }

    #[test]
    fn mountinfo_and_proc_mounts_parsers_read_the_mount_point() {
        let mountinfo = "36 1 8:17 / /mnt/elements rw,relatime - ext4 /dev/sdb1 rw\n";
        assert_eq!(
            parse_mountinfo_points(mountinfo),
            vec![PathBuf::from("/mnt/elements")]
        );
        let mounts = "/dev/sdb1 /mnt/elements ext4 rw,relatime 0 0\n";
        assert_eq!(
            parse_proc_mounts_points(mounts),
            vec![PathBuf::from("/mnt/elements")]
        );
        assert_eq!(unescape_mount("/mnt/My\\040Disk"), "/mnt/My Disk");
    }
}
