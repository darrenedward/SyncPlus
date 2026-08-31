use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use crate::{
    AnalysisError, AnalysisOutcome, FreshAnalysis, InventorySnapshotItem, ItemType,
    MetadataRequirements, NamingConflict, PeerSide, SourceInventorySnapshot, SyncProfile,
};

const DEFAULT_TEXT_PREVIEW_LIMIT: u64 = 1_048_576;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConflictKind {
    SamePath,
    PossibleDuplicateOrRename,
    DestinationCompatibility,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileReviewClassification {
    Text,
    Binary,
    Large,
    Unreadable,
    NonRegular,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictEvidence {
    side: PeerSide,
    relative_path: PathBuf,
    item_type: ItemType,
    size: u64,
    modified_at_unix_nanos: Option<i64>,
    readonly: bool,
    permissions: Option<u32>,
    symlink_target: Option<PathBuf>,
    sha256: Option<[u8; 32]>,
    classification: FileReviewClassification,
    text_preview: Option<String>,
}

impl ConflictEvidence {
    pub const fn side(&self) -> PeerSide {
        self.side
    }

    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub const fn item_type(&self) -> ItemType {
        self.item_type
    }

    pub const fn size(&self) -> u64 {
        self.size
    }

    pub const fn modified_at_unix_nanos(&self) -> Option<i64> {
        self.modified_at_unix_nanos
    }

    pub const fn is_readonly(&self) -> bool {
        self.readonly
    }

    pub const fn permissions(&self) -> Option<u32> {
        self.permissions
    }

    pub fn symlink_target(&self) -> Option<&Path> {
        self.symlink_target.as_deref()
    }

    pub fn sha256(&self) -> Option<&[u8; 32]> {
        self.sha256.as_ref()
    }

    pub const fn classification(&self) -> FileReviewClassification {
        self.classification
    }

    pub fn text_preview(&self) -> Option<&str> {
        self.text_preview.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictEntry {
    kind: ConflictKind,
    relative_path: PathBuf,
    related_path: Option<PathBuf>,
    destination_path: Option<PathBuf>,
    compatibility_rule: Option<crate::NamingRule>,
    evidence: Vec<ConflictEvidence>,
}

impl ConflictEntry {
    pub const fn kind(&self) -> ConflictKind {
        self.kind
    }

    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub fn related_path(&self) -> Option<&Path> {
        self.related_path.as_deref()
    }

    pub fn destination_path(&self) -> Option<&Path> {
        self.destination_path.as_deref()
    }

    pub const fn compatibility_rule(&self) -> Option<crate::NamingRule> {
        self.compatibility_rule
    }

    pub fn evidence(&self) -> &[ConflictEvidence] {
        &self.evidence
    }

    /// Conflict Review is an inspection boundary. It never contains an
    /// implicit winner or an operation that can mutate either peer.
    pub const fn is_read_only(&self) -> bool {
        true
    }

    /// Every review entry uses the same explicit whole-file decision set. The
    /// selected decision is validated separately before it can become an
    /// executable resolution plan.
    pub const fn available_resolutions(&self) -> &'static [crate::ConflictResolution; 5] {
        crate::ConflictResolution::all()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConflictReview {
    entries: Vec<ConflictEntry>,
}

impl ConflictReview {
    pub fn from_profile(profile: &SyncProfile) -> Result<Self, AnalysisError> {
        let analysis = FreshAnalysis::analyze(profile)?;
        Ok(Self::from_analysis(&analysis))
    }

    pub fn from_analysis(analysis: &FreshAnalysis) -> Self {
        let peer_a = SourceInventorySnapshot::from_inventory(analysis.source_inventory());
        let peer_b = SourceInventorySnapshot::from_inventory(analysis.destination_inventory());
        Self::from_inventories(
            &peer_a,
            &peer_b,
            analysis.specification().options().metadata(),
        )
    }

    pub fn from_inventories(
        peer_a: &SourceInventorySnapshot,
        peer_b: &SourceInventorySnapshot,
        metadata: MetadataRequirements,
    ) -> Self {
        Self::from_inventories_with_limit(
            peer_a,
            peer_b,
            metadata,
            DEFAULT_TEXT_PREVIEW_LIMIT,
        )
    }

    pub fn from_inventories_with_compatibility_conflicts(
        peer_a: &SourceInventorySnapshot,
        peer_b: &SourceInventorySnapshot,
        metadata: MetadataRequirements,
        compatibility_conflicts: &[NamingConflict],
    ) -> Self {
        let mut review = Self::from_inventories(peer_a, peer_b, metadata);
        review.add_compatibility_conflicts(compatibility_conflicts);
        review
    }

    pub fn from_inventories_with_limit(
        peer_a: &SourceInventorySnapshot,
        peer_b: &SourceInventorySnapshot,
        metadata: MetadataRequirements,
        text_preview_limit: u64,
    ) -> Self {
        let mut entries = Vec::new();
        let equality = MirrorReviewEquality::new(metadata);
        let mut all_paths = BTreeSet::new();
        all_paths.extend(
            peer_a
                .items()
                .iter()
                .filter(|item| item.outcome() == AnalysisOutcome::Included)
                .map(|item| item.relative_path().to_path_buf()),
        );
        all_paths.extend(
            peer_b
                .items()
                .iter()
                .filter(|item| item.outcome() == AnalysisOutcome::Included)
                .map(|item| item.relative_path().to_path_buf()),
        );

        for relative_path in &all_paths {
            let Some(left) = peer_a.item(relative_path) else { continue };
            let Some(right) = peer_b.item(relative_path) else { continue };
            if equality.equal(left, right) {
                continue;
            }
            entries.push(ConflictEntry {
                kind: ConflictKind::SamePath,
                relative_path: relative_path.clone(),
                related_path: None,
                destination_path: None,
                compatibility_rule: None,
                evidence: vec![
                    review_evidence(peer_a, PeerSide::PeerA, left, text_preview_limit),
                    review_evidence(peer_b, PeerSide::PeerB, right, text_preview_limit),
                ],
            });
        }

        let mut locations = Vec::new();
        for (side, inventory) in [(PeerSide::PeerA, peer_a), (PeerSide::PeerB, peer_b)] {
            for item in inventory
                .items()
                .iter()
                .filter(|item| item.outcome() == AnalysisOutcome::Included)
            {
                if item.item_type() == ItemType::RegularFile {
                    if let Some(hash) = item.content_fingerprint() {
                        locations.push((
                            *hash,
                            side,
                            item.relative_path().to_path_buf(),
                            review_evidence(inventory, side, item, text_preview_limit),
                        ));
                    }
                }
            }
        }
        locations.sort_by(|left, right| {
            side_rank(left.1)
                .cmp(&side_rank(right.1))
                .then_with(|| left.2.cmp(&right.2))
        });
        for (index, (hash, _side, path, evidence)) in locations.iter().enumerate() {
            for (other_hash, _other_side, other_path, other_evidence) in
                locations.iter().skip(index + 1)
            {
                if hash != other_hash || path == other_path {
                    continue;
                }
                entries.push(ConflictEntry {
                    kind: ConflictKind::PossibleDuplicateOrRename,
                    relative_path: path.clone(),
                    related_path: Some(other_path.clone()),
                    destination_path: None,
                    compatibility_rule: None,
                    evidence: vec![evidence.clone(), other_evidence.clone()],
                });
            }
        }

        Self { entries }
    }

    pub fn add_compatibility_conflicts(&mut self, conflicts: &[NamingConflict]) {
        self.entries.extend(conflicts.iter().map(|conflict| ConflictEntry {
            kind: ConflictKind::DestinationCompatibility,
            relative_path: conflict.source_path().to_path_buf(),
            related_path: conflict.related_path().map(Path::to_path_buf),
            destination_path: Some(conflict.destination_path().to_path_buf()),
            compatibility_rule: Some(conflict.rule()),
            evidence: Vec::new(),
        }));
        self.entries.sort_by(|left, right| {
            left.relative_path
                .cmp(&right.relative_path)
                .then_with(|| left.kind.cmp(&right.kind))
        });
    }

    pub fn entries(&self) -> &[ConflictEntry] {
        &self.entries
    }

    pub const fn is_read_only(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone, Copy)]
struct MirrorReviewEquality {
    metadata: MetadataRequirements,
}

impl MirrorReviewEquality {
    const fn new(metadata: MetadataRequirements) -> Self {
        Self { metadata }
    }

    fn equal(&self, left: &InventorySnapshotItem, right: &InventorySnapshotItem) -> bool {
        if left.item_type() != right.item_type() {
            return false;
        }
        if self.metadata.specialist_metadata().any() {
            return false;
        }
        if left.item_type() == ItemType::RegularFile
            && (left.size() != right.size()
                || left.content_fingerprint().is_none()
                || left.content_fingerprint() != right.content_fingerprint())
        {
            return false;
        }
        if self.metadata.executable_permissions()
            && left.executable_permissions() != right.executable_permissions()
        {
            return false;
        }
        if self.metadata.symlink_targets() && left.symlink_target() != right.symlink_target() {
            return false;
        }
        self.metadata.timestamps()
            .then(|| {
                left.modified_at_unix_nanos() == right.modified_at_unix_nanos()
            })
            .unwrap_or(true)
    }
}

fn review_evidence(
    inventory: &SourceInventorySnapshot,
    side: PeerSide,
    item: &InventorySnapshotItem,
    text_preview_limit: u64,
) -> ConflictEvidence {
    let (classification, text_preview) = if item.item_type() != ItemType::RegularFile {
        (FileReviewClassification::NonRegular, None)
    } else if item.content_fingerprint().is_none() {
        (FileReviewClassification::Unreadable, None)
    } else if item.size() > text_preview_limit {
        (FileReviewClassification::Large, None)
    } else {
        classify_file(
            &inventory.root().join(item.relative_path()),
            text_preview_limit,
        )
    };
    ConflictEvidence {
        side,
        relative_path: item.relative_path().to_path_buf(),
        item_type: item.item_type(),
        size: item.size(),
        modified_at_unix_nanos: item.modified_at_unix_nanos(),
        readonly: item.is_readonly(),
        permissions: item.permissions(),
        symlink_target: item.symlink_target().map(Path::to_path_buf),
        sha256: item.content_fingerprint().copied(),
        classification,
        text_preview,
    }
}

fn classify_file(path: &Path, text_preview_limit: u64) -> (FileReviewClassification, Option<String>) {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let Ok(file) = options.open(path) else {
        return (FileReviewClassification::Unreadable, None);
    };
    let mut bytes = Vec::new();
    if file
        .take(text_preview_limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .is_err()
    {
        return (FileReviewClassification::Unreadable, None);
    }
    if bytes.len() as u64 > text_preview_limit {
        return (FileReviewClassification::Large, None);
    }
    if bytes.contains(&0) || std::str::from_utf8(&bytes).is_err() {
        return (FileReviewClassification::Binary, None);
    }
    (
        FileReviewClassification::Text,
        Some(String::from_utf8(bytes).expect("UTF-8 was checked above")),
    )
}

const fn side_rank(side: PeerSide) -> u8 {
    match side {
        PeerSide::PeerA => 0,
        PeerSide::PeerB => 1,
    }
}
