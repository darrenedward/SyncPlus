use std::fmt;

use crate::SshPeer;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SshHost {
    server: String,
    port: u16,
}

impl SshHost {
    pub fn from_peer(peer: &SshPeer) -> Self {
        Self {
            server: peer.server().to_owned(),
            port: peer.port(),
        }
    }

    pub fn server(&self) -> &str {
        &self.server
    }

    pub const fn port(&self) -> u16 {
        self.port
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SshHostFingerprint {
    digest: [u8; 32],
}

impl SshHostFingerprint {
    pub const fn sha256(digest: [u8; 32]) -> Self {
        Self { digest }
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub const fn algorithm(&self) -> &'static str {
        "sha256"
    }

    pub(crate) fn from_storage(
        algorithm: &str,
        digest: &[u8],
    ) -> Result<Self, SshHostFingerprintError> {
        if algorithm != "sha256" {
            return Err(SshHostFingerprintError::UnsupportedAlgorithm);
        }
        let digest: [u8; 32] = digest
            .try_into()
            .map_err(|_| SshHostFingerprintError::InvalidDigestLength)?;
        Ok(Self::sha256(digest))
    }
}

impl fmt::Display for SshHostFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SHA256:")?;
        for byte in self.digest {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshHostFingerprintError {
    UnsupportedAlgorithm,
    InvalidDigestLength,
}

impl fmt::Display for SshHostFingerprintError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnsupportedAlgorithm => "unsupported SSH host fingerprint algorithm",
            Self::InvalidDigestLength => "invalid SSH host fingerprint digest length",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SshHostFingerprintError {}

pub trait SshHostIdentityProbe {
    fn probe(&self, peer: &SshPeer) -> Result<SshHostFingerprint, SshHostIdentityError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshHostIdentityError {
    ConnectionUnavailable,
    FingerprintUnavailable,
    ProbeFailed,
}

impl fmt::Display for SshHostIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ConnectionUnavailable => "SSH host identity connection is unavailable",
            Self::FingerprintUnavailable => "the SSH host did not provide a usable fingerprint",
            Self::ProbeFailed => "the SSH host identity probe failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SshHostIdentityError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostTrustDecision {
    FirstUseApprovalRequired {
        host: SshHost,
        observed: SshHostFingerprint,
    },
    Approved {
        host: SshHost,
        fingerprint: SshHostFingerprint,
    },
    ChangedFingerprint {
        host: SshHost,
        approved: SshHostFingerprint,
        observed: SshHostFingerprint,
    },
}

impl HostTrustDecision {
    pub const fn is_approved(&self) -> bool {
        matches!(self, Self::Approved { .. })
    }

    pub(crate) fn into_permit(self) -> Result<SshHostTrustPermit, HostTrustError> {
        match self {
            Self::Approved { host, fingerprint } => Ok(SshHostTrustPermit { host, fingerprint }),
            Self::FirstUseApprovalRequired { .. } => {
                Err(HostTrustError::FirstUseApprovalRequired)
            }
            Self::ChangedFingerprint { .. } => Err(HostTrustError::ChangedFingerprintRejected),
        }
    }

    fn host(&self) -> &SshHost {
        match self {
            Self::FirstUseApprovalRequired { host, .. }
            | Self::Approved { host, .. }
            | Self::ChangedFingerprint { host, .. } => host,
        }
    }

    fn observed(&self) -> &SshHostFingerprint {
        match self {
            Self::FirstUseApprovalRequired { observed, .. }
            | Self::ChangedFingerprint { observed, .. } => observed,
            Self::Approved { fingerprint, .. } => fingerprint,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshHostTrustPermit {
    host: SshHost,
    fingerprint: SshHostFingerprint,
}

impl SshHostTrustPermit {
    pub fn host(&self) -> &SshHost {
        &self.host
    }

    pub fn fingerprint(&self) -> &SshHostFingerprint {
        &self.fingerprint
    }
}

impl fmt::Display for HostTrustDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FirstUseApprovalRequired { host, observed } => write!(
                formatter,
                "SSH host {}:{} presented fingerprint {}. Explicit approval is required before any transfer.",
                host.server, host.port, observed
            ),
            Self::Approved { host, fingerprint } => write!(
                formatter,
                "SSH host {}:{} matches the approved fingerprint {}.",
                host.server, host.port, fingerprint
            ),
            Self::ChangedFingerprint { host, approved, observed } => write!(
                formatter,
                "SSH host {}:{} presented fingerprint {}, but the approved fingerprint is {}. Connection rejected; review the server identity before continuing.",
                host.server, host.port, observed, approved
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostTrustMode {
    Interactive,
    Unattended,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostTrustStoreError {
    Storage(String),
}

impl fmt::Display for HostTrustStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(detail) => write!(formatter, "SSH host trust storage failed: {detail}"),
        }
    }
}

impl std::error::Error for HostTrustStoreError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostTrustError {
    IdentityProbe(SshHostIdentityError),
    Store(HostTrustStoreError),
    FirstUseApprovalRequired,
    ChangedFingerprintRejected,
    InteractiveApprovalRequired,
    DecisionForDifferentHost,
}

impl fmt::Display for HostTrustError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdentityProbe(error) => error.fmt(formatter),
            Self::Store(error) => error.fmt(formatter),
            Self::FirstUseApprovalRequired => formatter.write_str(
                "SSH host identity requires explicit approval before any transfer",
            ),
            Self::ChangedFingerprintRejected => formatter.write_str(
                "SSH host identity changed and was rejected; review the server fingerprint",
            ),
            Self::InteractiveApprovalRequired => {
                formatter.write_str("SSH host approval requires an explicit interactive decision")
            }
            Self::DecisionForDifferentHost => {
                formatter.write_str("SSH host approval decision does not match this host")
            }
        }
    }
}

impl std::error::Error for HostTrustError {}

pub struct SshHostTrustController {
    store: crate::RunEvidenceStore,
}

impl SshHostTrustController {
    pub fn new(store: crate::RunEvidenceStore) -> Self {
        Self { store }
    }

    pub fn inspect<P: SshHostIdentityProbe>(
        &self,
        peer: &SshPeer,
        probe: &P,
    ) -> Result<HostTrustDecision, HostTrustError> {
        let host = SshHost::from_peer(peer);
        let observed = probe.probe(peer).map_err(HostTrustError::IdentityProbe)?;
        let approved = self
            .store
            .load_ssh_host_fingerprint(&host)
            .map_err(HostTrustError::Store)?;
        Ok(match approved {
            None => HostTrustDecision::FirstUseApprovalRequired { host, observed },
            Some(approved) if approved == observed => HostTrustDecision::Approved {
                host,
                fingerprint: observed,
            },
            Some(approved) => HostTrustDecision::ChangedFingerprint { host, approved, observed },
        })
    }

    pub fn pre_mutation_permit<P: SshHostIdentityProbe>(
        &self,
        peer: &SshPeer,
        probe: &P,
    ) -> Result<SshHostTrustPermit, HostTrustError> {
        self.inspect(peer, probe)?.into_permit()
    }

    pub fn approve(
        &mut self,
        peer: &SshPeer,
        decision: &HostTrustDecision,
        mode: HostTrustMode,
    ) -> Result<SshHostFingerprint, HostTrustError> {
        if mode != HostTrustMode::Interactive {
            return Err(HostTrustError::InteractiveApprovalRequired);
        }
        if decision.host() != &SshHost::from_peer(peer) {
            return Err(HostTrustError::DecisionForDifferentHost);
        }
        if matches!(decision, HostTrustDecision::ChangedFingerprint { .. }) {
            return Err(HostTrustError::ChangedFingerprintRejected);
        }
        let host = decision.host().to_owned();
        let observed = decision.observed().to_owned();
        self.store
            .approve_ssh_host_fingerprint(&host, &observed)
            .map_err(HostTrustError::Store)?;
        Ok(observed)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        HostTrustDecision, HostTrustError, HostTrustMode, Peer, RunEvidenceStore, SshAuthentication,
        SshHost, SshHostFingerprint, SshHostIdentityError, SshHostIdentityProbe,
        SshHostTrustController, SshPeer,
    };

    struct FixedProbe(SshHostFingerprint);

    impl SshHostIdentityProbe for FixedProbe {
        fn probe(&self, _peer: &SshPeer) -> Result<SshHostFingerprint, SshHostIdentityError> {
            Ok(self.0.clone())
        }
    }

    fn peer() -> SshPeer {
        SshPeer::new(
            "backup.example.test",
            "sync-user",
            2222,
            None,
            SshAuthentication::Agent,
            "/srv/sync",
        )
        .expect("SSH fixture should be valid")
    }

    fn fingerprint(value: u8) -> SshHostFingerprint {
        SshHostFingerprint::sha256([value; 32])
    }

    #[test]
    fn first_use_requires_explicit_approval_and_exposes_only_the_fingerprint() {
        let controller = SshHostTrustController::new(
            RunEvidenceStore::open_in_memory().expect("SQLite store should open"),
        );
        let decision = controller
            .inspect(&peer(), &FixedProbe(fingerprint(1)))
            .expect("fingerprint probe should succeed");

        assert_eq!(
            decision,
            HostTrustDecision::FirstUseApprovalRequired {
                host: SshHost::from_peer(&peer()),
                observed: fingerprint(1),
            }
        );
        assert!(!decision.is_approved());
        assert_eq!(
            controller.pre_mutation_permit(&peer(), &FixedProbe(fingerprint(1))),
            Err(HostTrustError::FirstUseApprovalRequired),
        );
        assert!(decision.to_string().contains("Explicit approval is required"));
        assert!(decision.to_string().contains(&fingerprint(1).to_string()));
    }

    #[test]
    fn unchanged_fingerprint_is_approved_but_changed_fingerprint_requires_review() {
        let host = SshHost::from_peer(&peer());
        let mut store = RunEvidenceStore::open_in_memory().expect("SQLite store should open");
        store
            .approve_ssh_host_fingerprint(&host, &fingerprint(1))
            .expect("fingerprint should persist");
        let controller = SshHostTrustController::new(store);

        let unchanged = controller
            .inspect(&peer(), &FixedProbe(fingerprint(1)))
            .expect("fingerprint inspection should succeed");
        assert_eq!(unchanged, HostTrustDecision::Approved { host: host.clone(), fingerprint: fingerprint(1) });
        assert!(unchanged.is_approved());
        let permit = controller
            .pre_mutation_permit(&peer(), &FixedProbe(fingerprint(1)))
            .expect("unchanged approved fingerprint should permit mutation");
        assert_eq!(permit.host(), &host);
        assert_eq!(permit.fingerprint(), &fingerprint(1));

        let changed = controller
            .inspect(&peer(), &FixedProbe(fingerprint(2)))
            .expect("fingerprint inspection should succeed");
        assert_eq!(
            changed,
            HostTrustDecision::ChangedFingerprint {
                host,
                approved: fingerprint(1),
                observed: fingerprint(2),
            }
        );
        assert!(!changed.is_approved());
        assert_eq!(
            controller.pre_mutation_permit(&peer(), &FixedProbe(fingerprint(2))),
            Err(HostTrustError::ChangedFingerprintRejected),
        );
        assert_eq!(
            controller
                .inspect(&peer(), &FixedProbe(fingerprint(1)))
                .unwrap(),
            HostTrustDecision::Approved {
                host: SshHost::from_peer(&peer()),
                fingerprint: fingerprint(1),
            },
            "inspection must not replace the approved fingerprint"
        );
        assert!(changed.to_string().contains("rejected"));
        assert!(changed.to_string().contains("review"));
    }

    #[test]
    fn unattended_mode_cannot_approve_first_use_or_changed_identity() {
        let mut controller = SshHostTrustController::new(
            RunEvidenceStore::open_in_memory().expect("SQLite store should open"),
        );
        let peer = peer();
        let decision = controller
            .inspect(&peer, &FixedProbe(fingerprint(1)))
            .expect("fingerprint inspection should succeed");

        assert_eq!(
            controller.approve(&peer, &decision, HostTrustMode::Unattended),
            Err(HostTrustError::InteractiveApprovalRequired),
        );
        assert!(matches!(
            controller
                .inspect(&peer, &FixedProbe(fingerprint(1)))
                .expect("fingerprint inspection should succeed"),
            HostTrustDecision::FirstUseApprovalRequired { .. }
        ));
    }

    #[test]
    fn interactive_approval_persists_the_nonsecret_fingerprint() {
        let mut controller = SshHostTrustController::new(
            RunEvidenceStore::open_in_memory().expect("SQLite store should open"),
        );
        let peer = peer();
        let decision = controller
            .inspect(&peer, &FixedProbe(fingerprint(1)))
            .expect("fingerprint inspection should succeed");

        assert_eq!(
            controller.approve(&peer, &decision, HostTrustMode::Interactive),
            Ok(fingerprint(1)),
        );
        assert_eq!(
            controller
                .inspect(&peer, &FixedProbe(fingerprint(1)))
                .expect("fingerprint inspection should succeed"),
            HostTrustDecision::Approved {
                host: SshHost::from_peer(&peer),
                fingerprint: fingerprint(1),
            }
        );
    }

    #[test]
    fn sqlite_trust_store_round_trips_fingerprint_by_server_and_port() {
        let mut store = RunEvidenceStore::open_in_memory().expect("SQLite store should open");
        let peer = Peer::from_ssh("SSH peer", peer());
        let host = SshHost::from_peer(peer.ssh_peer().expect("SSH peer"));
        let expected = fingerprint(3);

        store
            .approve_ssh_host_fingerprint(&host, &expected)
            .expect("fingerprint should persist");
        assert_eq!(
            store
                .load_ssh_host_fingerprint(&host)
                .expect("fingerprint should load"),
            Some(expected)
        );
    }
}
