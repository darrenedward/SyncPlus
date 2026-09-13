#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisKind {
    FolderCheck,
    DryRun,
}

impl AnalysisKind {
    pub const fn heading(self) -> &'static str {
        match self {
            Self::FolderCheck => "Checking folders",
            Self::DryRun => "Dry run in progress",
        }
    }

    pub const fn inventory(self) -> bool {
        matches!(self, Self::DryRun)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisPhase {
    CheckingFolders,
    ReadingFolders,
}

impl AnalysisPhase {
    pub const fn detail(self) -> &'static str {
        match self {
            Self::CheckingFolders => {
                "Checking that the source and destination folders are available."
            }
            Self::ReadingFolders => "Reading the current files in the selected folders.",
        }
    }
}

pub fn format_clock(seconds: u64) -> String {
    format!("{:02}:{:02}", seconds / 60, seconds % 60)
}

pub fn format_elapsed(seconds: u64) -> String {
    match seconds {
        0 => "just started".to_owned(),
        1 => "1 second".to_owned(),
        2..=59 => format!("{seconds} seconds"),
        _ => {
            let minutes = seconds / 60;
            let rest = seconds % 60;
            if rest == 0 {
                format!("{minutes} min")
            } else {
                format!("{minutes} min {rest} s")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AnalysisKind, AnalysisPhase, format_clock, format_elapsed};

    #[test]
    fn dry_run_phases_explain_the_current_work_without_implying_mutation() {
        assert_eq!(AnalysisKind::DryRun.heading(), "Dry run in progress");
        assert_eq!(AnalysisKind::FolderCheck.heading(), "Checking folders");
        assert!(
            AnalysisPhase::CheckingFolders
                .detail()
                .contains("folders are available")
        );
        assert!(
            AnalysisPhase::ReadingFolders
                .detail()
                .contains("Reading the current files")
        );
        assert!(
            !AnalysisPhase::ReadingFolders
                .detail()
                .to_ascii_lowercase()
                .contains("copied")
        );
    }

    #[test]
    fn elapsed_copy_stays_readable() {
        assert_eq!(format_elapsed(0), "just started");
        assert_eq!(format_elapsed(1), "1 second");
        assert_eq!(format_elapsed(12), "12 seconds");
        assert_eq!(format_elapsed(60), "1 min");
        assert_eq!(format_elapsed(75), "1 min 15 s");
        assert_eq!(format_clock(9), "00:09");
        assert_eq!(format_clock(75), "01:15");
    }
}
