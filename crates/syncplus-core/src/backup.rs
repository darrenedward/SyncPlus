use std::{
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use rusqlite::{Connection, OpenFlags};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedBackup {
    path: PathBuf,
}

impl ValidatedBackup {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Debug)]
pub enum BackupError {
    InvalidPath(String),
    Io(io::Error),
    Sqlite(rusqlite::Error),
    Integrity(String),
    Compression(String),
    BackupNotFound,
    BackupNotValidated,
    LiveDatabaseHealthy,
    Quarantine(String),
    Rotation(String),
}

impl std::fmt::Display for BackupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPath(reason) => write!(formatter, "invalid database backup path: {reason}"),
            Self::Io(error) => write!(formatter, "database backup filesystem error: {error}"),
            Self::Sqlite(error) => write!(formatter, "database backup SQLite error: {error}"),
            Self::Integrity(reason) => write!(formatter, "database integrity check failed: {reason}"),
            Self::Compression(reason) => write!(formatter, "database backup compression failed: {reason}"),
            Self::BackupNotFound => formatter.write_str("the selected database backup was not found"),
            Self::BackupNotValidated => formatter.write_str("the selected database backup is not validated"),
            Self::LiveDatabaseHealthy => formatter.write_str("the live database is healthy; explicit restore would overwrite it"),
            Self::Quarantine(reason) => write!(formatter, "corrupt database quarantine failed: {reason}"),
            Self::Rotation(reason) => write!(formatter, "database backup rotation failed: {reason}"),
        }
    }
}

impl std::error::Error for BackupError {}

impl From<io::Error> for BackupError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rusqlite::Error> for BackupError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

#[derive(Debug, Clone)]
pub struct DatabaseBackupManager {
    database_path: PathBuf,
    backup_dir: PathBuf,
    quarantine_dir: PathBuf,
    temp_dir: PathBuf,
}

impl DatabaseBackupManager {
    /// Build the manager for the canonical Application Database and its XDG
    /// backup, quarantine, and temporary-data locations.
    pub fn for_database(database_path: impl AsRef<Path>) -> Result<Self, BackupError> {
        let database_path = validate_absolute_path(database_path.as_ref(), "database")?;
        let app_root = database_path
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| {
                BackupError::InvalidPath("database has no application-data parent".into())
            })?;
        let cache_home = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .map(|home| home.join(".cache"))
            })
            .ok_or_else(|| BackupError::InvalidPath("XDG_CACHE_HOME or HOME is required".into()))?;
        let cache_home = validate_absolute_path(&cache_home, "cache")?;
        Ok(Self {
            database_path,
            backup_dir: app_root.join("backups"),
            quarantine_dir: app_root.join("quarantine"),
            temp_dir: cache_home.join("syncplus"),
        })
    }

    /// Construct a manager with explicit directories. Production callers
    /// should use `for_database`; explicit paths keep filesystem tests isolated.
    pub fn new(
        database_path: impl AsRef<Path>,
        backup_dir: impl AsRef<Path>,
        quarantine_dir: impl AsRef<Path>,
        temp_dir: impl AsRef<Path>,
    ) -> Result<Self, BackupError> {
        Ok(Self {
            database_path: validate_absolute_path(database_path.as_ref(), "database")?,
            backup_dir: validate_absolute_path(backup_dir.as_ref(), "backup")?,
            quarantine_dir: validate_absolute_path(quarantine_dir.as_ref(), "quarantine")?,
            temp_dir: validate_absolute_path(temp_dir.as_ref(), "temporary data")?,
        })
    }

    pub fn database_path(&self) -> &Path {
        &self.database_path
    }

    pub fn backup_dir(&self) -> &Path {
        &self.backup_dir
    }

    pub fn quarantine_dir(&self) -> &Path {
        &self.quarantine_dir
    }

    /// Create, independently validate, and rotate one consistent compressed
    /// snapshot. Rotation happens only after the new backup is validated.
    pub fn create_validated_backup(
        &self,
        live_connection: &Connection,
    ) -> Result<ValidatedBackup, BackupError> {
        self.ensure_layout()?;
        if let Ok(metadata) = fs::symlink_metadata(&self.database_path) {
            if !metadata.file_type().is_file() {
                return Err(BackupError::InvalidPath(
                    "live database path is not a regular file".into(),
                ));
            }
            set_private_path(&self.database_path)?;
            validate_sqlite_file(&self.database_path)?;
        }
        verify_connection(live_connection)?;

        let snapshot = self.temp_path("snapshot", "sqlite");
        // Keep the compressed staging file beside the final backup so the
        // validated installation is atomic even when XDG_CACHE_HOME is
        // mounted separately from application data.
        let compressed = self
            .backup_dir
            .join(format!(".syncplus-backup-{}.sqlite.gz", unique_token()));
        let final_path = self.backup_dir.join(format!(
            "syncplus-{}.sqlite.gz",
            unique_token()
        ));
        let result = (|| {
            vacuum_into(live_connection, &snapshot)?;
            validate_sqlite_file(&snapshot)?;
            compress_file(&snapshot, &compressed)?;
            validate_compressed_backup(&compressed, &self.temp_dir)?;
            // A hard link gives create-without-replacement semantics for the
            // final name, while keeping the validated bytes on one filesystem.
            fs::hard_link(&compressed, &final_path)?;
            fs::remove_file(&compressed)?;
            sync_directory(&self.backup_dir)?;
            let validated = ValidatedBackup { path: final_path };
            self.rotate_validated_backups(&validated)?;
            Ok(validated)
        })();
        let _ = fs::remove_file(&snapshot);
        let _ = fs::remove_file(&compressed);
        result
    }

    /// Return only compressed backups that independently decompress and pass
    /// SQLite integrity validation. Invalid files remain untouched for diagnosis.
    pub fn list_validated_backups(&self) -> Result<Vec<ValidatedBackup>, BackupError> {
        self.ensure_layout()?;
        let mut backups = Vec::new();
        for entry in fs::read_dir(&self.backup_dir)? {
            let path = entry?.path();
            if !is_backup_name(&path) || !is_regular_file(&path) {
                continue;
            }
            if validate_compressed_backup(&path, &self.temp_dir).is_ok() {
                backups.push(ValidatedBackup { path });
            }
        }
        backups.sort_by(|left, right| left.path.cmp(&right.path));
        backups.reverse();
        Ok(backups)
    }

    /// Explicitly restore one currently validated backup. A healthy live
    /// database is never replaced; a corrupt/unverifiable one is quarantined
    /// first, and failures leave the application without a trusted live DB.
    pub fn restore_validated_backup(
        &self,
        selected: impl AsRef<Path>,
    ) -> Result<PathBuf, BackupError> {
        self.ensure_layout()?;
        let selected = self.validate_selected_backup(selected.as_ref())?;
        if let Ok(metadata) = fs::symlink_metadata(&self.database_path) {
            if !metadata.file_type().is_file() {
                return Err(BackupError::InvalidPath(
                    "live database path is not a regular file".into(),
                ));
            }
            if validate_sqlite_file(&self.database_path).is_ok() {
                return Err(BackupError::LiveDatabaseHealthy);
            }
            self.quarantine_live_database()?;
        }

        let restored = self.temp_path("restore", "sqlite");
        let mut installed = false;
        let result = (|| {
            decompress_file(&selected.path, &restored)?;
            validate_sqlite_file(&restored)?;
            install_database(&restored, &self.database_path)?;
            installed = true;
            validate_sqlite_file(&self.database_path)?;
            Ok(self.database_path.clone())
        })();
        if installed && result.is_err() {
            let _ = fs::remove_file(&self.database_path);
        }
        let _ = fs::remove_file(&restored);
        result
    }

    /// Move an unverifiable live database and its SQLite sidecars to the
    /// recoverable quarantine directory. Healthy databases are rejected.
    pub fn quarantine_live_database(&self) -> Result<PathBuf, BackupError> {
        self.ensure_layout()?;
        let metadata = fs::symlink_metadata(&self.database_path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                BackupError::BackupNotFound
            } else {
                BackupError::Io(error)
            }
        })?;
        if !metadata.file_type().is_file() {
            return Err(BackupError::InvalidPath(
                "live database path is not a regular file".into(),
            ));
        }
        if validate_sqlite_file(&self.database_path).is_ok() {
            return Err(BackupError::LiveDatabaseHealthy);
        }
        let mut sidecars = Vec::new();
        for sidecar in sqlite_sidecars(&self.database_path) {
            match fs::symlink_metadata(&sidecar) {
                Ok(sidecar_metadata) if sidecar_metadata.file_type().is_file() => {
                    sidecars.push(sidecar)
                }
                Ok(_) => {
                    return Err(BackupError::Quarantine(format!(
                        "SQLite sidecar {sidecar:?} is not a regular file"
                    )))
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(BackupError::Io(error)),
            }
        }
        let quarantine_path = self
            .quarantine_dir
            .join(format!("syncplus-corrupt-{}.sqlite", unique_token()));
        let quarantine_sidecars = sidecars
            .iter()
            .map(|sidecar| {
                let suffix = if sidecar == &sqlite_sidecars(&self.database_path)[0] {
                    "-wal"
                } else {
                    "-shm"
                };
                append_suffix(&quarantine_path, suffix)
            })
            .collect::<Vec<_>>();
        fs::rename(&self.database_path, &quarantine_path).map_err(|error| {
            BackupError::Quarantine(format!("could not retain the corrupt database: {error}"))
        })?;
        for (sidecar, quarantine_sidecar) in sidecars.iter().zip(quarantine_sidecars) {
            if let Err(error) = fs::rename(sidecar, &quarantine_sidecar) {
                return Err(BackupError::Quarantine(format!(
                    "could not retain SQLite sidecar {sidecar:?}: {error}"
                )));
            }
            set_private_path(&quarantine_sidecar)?;
        }
        set_private_path(&quarantine_path)?;
        sync_directory(&self.quarantine_dir)?;
        Ok(quarantine_path)
    }

    fn ensure_layout(&self) -> Result<(), BackupError> {
        ensure_private_dir(&self.backup_dir)?;
        ensure_private_dir(&self.quarantine_dir)?;
        ensure_private_dir(&self.temp_dir)
    }

    fn temp_path(&self, label: &str, extension: &str) -> PathBuf {
        self.temp_dir
            .join(format!(".syncplus-{label}-{}.{}", unique_token(), extension))
    }

    fn validate_selected_backup(&self, selected: &Path) -> Result<ValidatedBackup, BackupError> {
        let selected = validate_absolute_path(selected, "selected backup")?;
        if selected.parent() != Some(self.backup_dir.as_path()) || !is_backup_name(&selected) {
            return Err(BackupError::BackupNotValidated);
        }
        self.list_validated_backups()?
            .into_iter()
            .find(|backup| backup.path == selected)
            .ok_or(BackupError::BackupNotValidated)
    }

    fn rotate_validated_backups(&self, newest: &ValidatedBackup) -> Result<(), BackupError> {
        let mut backups = self.list_validated_backups()?;
        while backups.len() > 2 {
            let oldest = backups.pop().ok_or_else(|| {
                BackupError::Rotation("validated backup set became empty".into())
            })?;
            if oldest.path == newest.path {
                return Err(BackupError::Rotation(
                    "rotation selected the newly validated backup".into(),
                ));
            }
            fs::remove_file(&oldest.path).map_err(|error| {
                BackupError::Rotation(format!("could not remove the oldest validated backup: {error}"))
            })?;
        }
        sync_directory(&self.backup_dir)?;
        Ok(())
    }
}

fn validate_absolute_path(path: &Path, label: &str) -> Result<PathBuf, BackupError> {
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return Err(BackupError::InvalidPath(format!("{label} path must be absolute")));
    }
    Ok(path.to_path_buf())
}

fn ensure_private_dir(path: &Path) -> Result<(), BackupError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() => {
            return Err(BackupError::InvalidPath(format!("{path:?} is not a private directory")))
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir_all(path)?,
        Err(error) => return Err(BackupError::Io(error)),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn set_private_path(path: &Path) -> Result<(), BackupError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_file())
        .unwrap_or(false)
}

fn is_backup_name(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("syncplus-") && name.ends_with(".sqlite.gz"))
}

fn sqlite_sidecars(database_path: &Path) -> [PathBuf; 2] {
    [append_suffix(database_path, "-wal"), append_suffix(database_path, "-shm")]
}

fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn unique_token() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("{now}-{}", NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed))
}

fn vacuum_into(connection: &Connection, destination: &Path) -> Result<(), BackupError> {
    let destination = destination.to_str().ok_or_else(|| {
        BackupError::InvalidPath("temporary SQLite path is not valid UTF-8".into())
    })?;
    connection.execute("VACUUM INTO ?1", [destination])?;
    set_private_path(Path::new(destination))?;
    Ok(())
}

fn verify_connection(connection: &Connection) -> Result<(), BackupError> {
    let result: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if result == "ok" {
        Ok(())
    } else {
        Err(BackupError::Integrity(result))
    }
}

fn open_read_only(path: &Path) -> Result<Connection, BackupError> {
    Ok(Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?)
}

fn validate_sqlite_file(path: &Path) -> Result<(), BackupError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(BackupError::Integrity(format!("{path:?} is not a regular database file")));
    }
    let connection = open_read_only(path)?;
    verify_connection(&connection)
}

fn compress_file(source: &Path, destination: &Path) -> Result<(), BackupError> {
    let input = File::open(source)?;
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    set_private_path(destination)?;
    let mut encoder = GzEncoder::new(output, Compression::default());
    let mut input = input;
    io::copy(&mut input, &mut encoder)?;
    let output = encoder
        .finish()
        .map_err(|error| BackupError::Compression(error.to_string()))?;
    output.sync_all()?;
    Ok(())
}

fn decompress_file(source: &Path, destination: &Path) -> Result<(), BackupError> {
    let input = File::open(source)?;
    let mut decoder = GzDecoder::new(input);
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    set_private_path(destination)?;
    let mut output = output;
    io::copy(&mut decoder, &mut output)
        .map_err(|error| BackupError::Compression(error.to_string()))?;
    output.sync_all()?;
    Ok(())
}

fn validate_compressed_backup(source: &Path, temp_dir: &Path) -> Result<(), BackupError> {
    if !is_regular_file(source) {
        return Err(BackupError::BackupNotValidated);
    }
    let validation_path = temp_dir.join(format!(".syncplus-validate-{}.sqlite", unique_token()));
    let result = (|| {
        decompress_file(source, &validation_path)?;
        validate_sqlite_file(&validation_path)
    })();
    let _ = fs::remove_file(&validation_path);
    result
}

fn install_database(source: &Path, destination: &Path) -> Result<(), BackupError> {
    if fs::symlink_metadata(destination).is_ok() {
        return Err(BackupError::Quarantine(
            "live database appeared during explicit restore".into(),
        ));
    }
    let mut input = File::open(source)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    if let Err(error) = set_private_path(destination) {
        let _ = fs::remove_file(destination);
        return Err(error);
    }
    let result = (|| {
        io::copy(&mut input, &mut output)?;
        output.sync_all()?;
        sync_directory(destination.parent().ok_or_else(|| {
            BackupError::InvalidPath("live database has no parent".into())
        })?)?;
        Ok::<(), BackupError>(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(destination);
        return Err(error);
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), BackupError> {
    let directory = File::open(path)?;
    directory.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf, sync::atomic::AtomicU64};

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        manager: DatabaseBackupManager,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "syncplus-backup-test-{}-{}",
                std::process::id(),
                NEXT_TEST.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&root).unwrap();
            let manager = DatabaseBackupManager::new(
                root.join("syncplus.db"),
                root.join("backups"),
                root.join("quarantine"),
                root.join("tmp"),
            )
            .unwrap();
            Self { root, manager }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn connection(fixture: &Fixture) -> Connection {
        let connection = Connection::open(fixture.manager.database_path()).unwrap();
        connection
            .execute_batch("CREATE TABLE IF NOT EXISTS records (value TEXT NOT NULL);")
            .unwrap();
        connection
    }

    #[test]
    fn creates_gzip_backup_and_rotates_to_two_validated_backups() {
        let fixture = Fixture::new();
        let connection = connection(&fixture);
        fixture.manager.create_validated_backup(&connection).unwrap();
        connection.execute("INSERT INTO records VALUES (?1)", ["two"]).unwrap();
        fixture.manager.create_validated_backup(&connection).unwrap();
        connection.execute("INSERT INTO records VALUES (?1)", ["three"]).unwrap();
        fixture.manager.create_validated_backup(&connection).unwrap();

        let backups = fixture.manager.list_validated_backups().unwrap();
        assert_eq!(backups.len(), 2);
        assert!(backups.iter().all(|backup| backup.path().extension().is_some()));
    }

    #[test]
    fn corrupt_live_database_is_not_backed_up_and_good_backup_remains() {
        let fixture = Fixture::new();
        let connection = connection(&fixture);
        fixture.manager.create_validated_backup(&connection).unwrap();
        drop(connection);
        fs::write(fixture.manager.database_path(), b"not sqlite").unwrap();

        let corrupt = Connection::open(fixture.manager.database_path()).unwrap();
        assert!(matches!(
            fixture.manager.create_validated_backup(&corrupt),
            Err(BackupError::Sqlite(_) | BackupError::Integrity(_))
        ));
        assert_eq!(fixture.manager.list_validated_backups().unwrap().len(), 1);
    }

    #[test]
    fn explicit_restore_quarantines_corrupt_live_database() {
        let fixture = Fixture::new();
        let connection = connection(&fixture);
        fixture.manager.create_validated_backup(&connection).unwrap();
        drop(connection);
        let selected = fixture.manager.list_validated_backups().unwrap().remove(0);
        fs::write(fixture.manager.database_path(), b"corrupt").unwrap();

        fixture
            .manager
            .restore_validated_backup(selected.path())
            .unwrap();
        assert!(validate_sqlite_file(fixture.manager.database_path()).is_ok());
        let quarantined = fs::read_dir(fixture.manager.quarantine_dir())
            .unwrap()
            .filter_map(Result::ok)
            .count();
        assert_eq!(quarantined, 1);
    }

    #[test]
    fn explicit_restore_refuses_to_replace_a_healthy_live_database() {
        let fixture = Fixture::new();
        let connection = connection(&fixture);
        let backup = fixture.manager.create_validated_backup(&connection).unwrap();

        assert!(matches!(
            fixture.manager.restore_validated_backup(backup.path()),
            Err(BackupError::LiveDatabaseHealthy)
        ));
    }

    #[test]
    fn invalid_compressed_files_are_not_offered_for_restore() {
        let fixture = Fixture::new();
        let connection = connection(&fixture);
        fixture.manager.create_validated_backup(&connection).unwrap();
        fs::write(
            fixture.manager.backup_dir().join("syncplus-invalid.sqlite.gz"),
            b"not gzip",
        )
        .unwrap();

        let backups = fixture.manager.list_validated_backups().unwrap();
        assert_eq!(backups.len(), 1);
        assert!(!backups[0].path().ends_with("syncplus-invalid.sqlite.gz"));
    }

    #[cfg(unix)]
    #[test]
    fn database_backup_layout_uses_user_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = Fixture::new();
        let connection = connection(&fixture);
        let backup = fixture.manager.create_validated_backup(&connection).unwrap();

        assert_eq!(fs::metadata(fixture.manager.backup_dir()).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(fixture.manager.quarantine_dir()).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(fixture.manager.database_path()).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(backup.path()).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
