use std::{
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
};

use crate::RunId;

/// A path normalized without touching the filesystem.
///
/// Scope identity must work for paths that have not been created yet, so this
/// deliberately performs lexical normalization rather than `canonicalize`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerScope {
    path: PathBuf,
}

impl PeerScope {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: normalize_path(path.as_ref()),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn overlaps(&self, other: &Self) -> bool {
        self.path.starts_with(&other.path) || other.path.starts_with(&self.path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeLockOwner {
    profile_name: String,
    run_id: RunId,
}

impl ScopeLockOwner {
    pub fn new(profile_name: impl Into<String>, run_id: RunId) -> Self {
        Self {
            profile_name: profile_name.into(),
            run_id,
        }
    }

    pub fn profile_name(&self) -> &str {
        &self.profile_name
    }

    pub const fn run_id(&self) -> RunId {
        self.run_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeLockConflict {
    requested: PeerScope,
    held: PeerScope,
    owner: ScopeLockOwner,
}

impl ScopeLockConflict {
    pub fn requested(&self) -> &PeerScope {
        &self.requested
    }

    pub fn held(&self) -> &PeerScope {
        &self.held
    }

    pub fn owner(&self) -> &ScopeLockOwner {
        &self.owner
    }

    pub fn remediation(&self) -> String {
        format!(
            "wait for profile '{}' run {} to finish before starting this run",
            self.owner.profile_name(),
            self.owner.run_id().value()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeLockError {
    EmptyScopes,
    Conflict(ScopeLockConflict),
}

#[derive(Debug, Default)]
struct LockState {
    next_token: u64,
    held: Vec<HeldScope>,
}

#[derive(Debug)]
struct HeldScope {
    token: u64,
    scope: PeerScope,
    owner: ScopeLockOwner,
}

/// Thread-safe registry for all active profile runs in the process.
#[derive(Debug, Clone, Default)]
pub struct PeerScopeLockRegistry {
    state: Arc<Mutex<LockState>>,
}

impl PeerScopeLockRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Acquire all scopes atomically. No scope is held if any requested scope
    /// overlaps an existing scope or if the requested set is empty.
    pub fn acquire<I>(
        &self,
        owner: ScopeLockOwner,
        scopes: I,
    ) -> Result<PeerScopeLock, ScopeLockError>
    where
        I: IntoIterator<Item = PeerScope>,
    {
        let mut requested: Vec<_> = scopes.into_iter().collect();
        requested.sort_by(|left, right| left.path.cmp(&right.path));
        requested.dedup();
        if requested.is_empty() {
            return Err(ScopeLockError::EmptyScopes);
        }

        let mut state = self.state.lock().expect("scope lock registry is not poisoned");
        for requested_scope in &requested {
            if let Some(held_scope) = state
                .held
                .iter()
                .find(|held_scope| requested_scope.overlaps(&held_scope.scope))
            {
                return Err(ScopeLockError::Conflict(ScopeLockConflict {
                    requested: requested_scope.clone(),
                    held: held_scope.scope.clone(),
                    owner: held_scope.owner.clone(),
                }));
            }
        }

        state.next_token = state.next_token.wrapping_add(1).max(1);
        let token = state.next_token;
        state.held.extend(requested.into_iter().map(|scope| HeldScope {
            token,
            scope,
            owner: owner.clone(),
        }));

        Ok(PeerScopeLock {
            registry: self.clone(),
            token,
        })
    }

    fn release(&self, token: u64) {
        let mut state = self.state.lock().expect("scope lock registry is not poisoned");
        state.held.retain(|held_scope| held_scope.token != token);
    }
}

/// RAII lease held for the lifetime of an active run.
#[derive(Debug)]
pub struct PeerScopeLock {
    registry: PeerScopeLockRegistry,
    token: u64,
}

impl PeerScopeLock {
    pub(crate) const fn token(&self) -> u64 {
        self.token
    }
}

impl Drop for PeerScopeLock {
    fn drop(&mut self) {
        self.registry.release(self.token);
    }
}

fn normalize_path(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|directory| directory.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };

    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if normalized.file_name().is_some() {
                    normalized.pop();
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    normalized
}
