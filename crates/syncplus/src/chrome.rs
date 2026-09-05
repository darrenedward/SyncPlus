use syncplus_core::RunReportStatus;

/// Desktop chrome destinations. Recovery Review is a notice, not a peer item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChromeSurface {
    Overview,
    Profiles,
    SyncWorkspace,
    Reports,
    Settings,
    Help,
}

/// Selected chrome uses copper; unselected items share muted ink.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChromeAccent {
    Muted,
    Copper,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SidebarItem {
    pub surface: ChromeSurface,
    pub label: &'static str,
    pub selected: bool,
    pub accent: ChromeAccent,
}

pub const EMPTY_OVERVIEW_EYEBROW: &str = "Overview";
pub const EMPTY_OVERVIEW_TITLE: &str = "Create a Sync Profile";
pub const EMPTY_OVERVIEW_BODY: &str = "SyncPlus reviews a plan and waits for confirmation before anything is overwritten or removed. Create a Sync Profile to choose the folders.";
pub const EMPTY_OVERVIEW_PRIMARY: &str = "Create your first profile";

pub const POPULATED_OVERVIEW_EYEBROW: &str = "Overview";
pub const NO_SYNC_RUN_YET: &str = "No Sync Run yet";
pub const NEXT_ACTION_REVIEW_PLAN: &str = "Review the current plan";
pub const NEXT_ACTION_RECOVERY_REVIEW: &str = "Open Recovery Review";
pub const PRIMARY_SYNCHRONISE: &str = "Synchronise";
pub const PRIMARY_OPEN_RECOVERY: &str = "Open Recovery Review";
pub const RECOVERY_REVIEW_NOTICE: &str = "Recovery Review required";
pub const REPORTS_REVIEW_BADGE: &str = "Review";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OverviewAction {
    CreateProfile,
    Synchronise,
    OpenRecoveryReview,
}

impl OverviewAction {
    pub fn label(self) -> &'static str {
        match self {
            Self::CreateProfile => EMPTY_OVERVIEW_PRIMARY,
            Self::Synchronise => PRIMARY_SYNCHRONISE,
            Self::OpenRecoveryReview => PRIMARY_OPEN_RECOVERY,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OverviewModel {
    pub eyebrow: &'static str,
    pub title: String,
    pub body: String,
    pub primary_action: OverviewAction,
    pub last_run: String,
    pub next_safe_action: &'static str,
    pub recovery_notice: Option<&'static str>,
}

pub fn recovery_review_is_pending<I>(statuses: I) -> bool
where
    I: IntoIterator<Item = RunReportStatus>,
{
    statuses.into_iter().any(status_requires_recovery_review)
}

pub fn report_review_is_pending<I>(statuses: I) -> bool
where
    I: IntoIterator<Item = RunReportStatus>,
{
    statuses.into_iter().any(status_requires_report_review)
}

pub fn status_requires_recovery_review(status: RunReportStatus) -> bool {
    matches!(
        status,
        RunReportStatus::RecoveryReview | RunReportStatus::Interrupted
    )
}

pub fn status_requires_report_review(status: RunReportStatus) -> bool {
    status_requires_recovery_review(status)
        || status == RunReportStatus::CompletedWithReviewRequired
}

pub fn sidebar_items(current: ChromeSurface) -> Vec<SidebarItem> {
    const DESTINATIONS: [(ChromeSurface, &'static str); 6] = [
        (ChromeSurface::Overview, "Overview"),
        (ChromeSurface::Profiles, "Profiles"),
        (ChromeSurface::SyncWorkspace, "Sync workspace"),
        (ChromeSurface::Reports, "Run Reports"),
        (ChromeSurface::Settings, "Settings"),
        (ChromeSurface::Help, "Help & Support"),
    ];
    DESTINATIONS
        .into_iter()
        .map(|(surface, label)| {
            let selected = surface == current;
            SidebarItem {
                surface,
                label,
                selected,
                accent: if selected {
                    ChromeAccent::Copper
                } else {
                    ChromeAccent::Muted
                },
            }
        })
        .collect()
}

pub fn recovery_review_notice(pending: bool) -> Option<&'static str> {
    pending.then_some(RECOVERY_REVIEW_NOTICE)
}

pub fn reports_badge(pending: bool) -> Option<&'static str> {
    pending.then_some(REPORTS_REVIEW_BADGE)
}

pub fn empty_overview() -> OverviewModel {
    OverviewModel {
        eyebrow: EMPTY_OVERVIEW_EYEBROW,
        title: EMPTY_OVERVIEW_TITLE.to_owned(),
        body: EMPTY_OVERVIEW_BODY.to_owned(),
        primary_action: OverviewAction::CreateProfile,
        last_run: NO_SYNC_RUN_YET.to_owned(),
        next_safe_action: EMPTY_OVERVIEW_PRIMARY,
        recovery_notice: None,
    }
}

pub fn populated_overview(
    profile_name: &str,
    mode_label: &str,
    last_run: Option<RunReportStatus>,
    recovery_pending: bool,
) -> OverviewModel {
    let last_run = last_run_label(last_run);
    let (next_safe_action, primary_action, recovery_notice) = if recovery_pending {
        (
            NEXT_ACTION_RECOVERY_REVIEW,
            OverviewAction::OpenRecoveryReview,
            Some(RECOVERY_REVIEW_NOTICE),
        )
    } else {
        (NEXT_ACTION_REVIEW_PLAN, OverviewAction::Synchronise, None)
    };
    OverviewModel {
        eyebrow: POPULATED_OVERVIEW_EYEBROW,
        title: profile_name.to_owned(),
        body: format!("{mode_label}. {last_run}. Next safe action: {next_safe_action}."),
        primary_action,
        last_run,
        next_safe_action,
        recovery_notice,
    }
}

pub fn wizard_step_caption(selected: bool, completed: bool) -> &'static str {
    if selected {
        "Current step"
    } else if completed {
        "Complete"
    } else {
        "Upcoming"
    }
}

pub fn last_run_label(status: Option<RunReportStatus>) -> String {
    match status {
        None => NO_SYNC_RUN_YET.to_owned(),
        Some(status) => format!("Last Sync Run · {}", run_report_status_phrase(status)),
    }
}

pub fn run_report_status_phrase(status: RunReportStatus) -> &'static str {
    match status {
        RunReportStatus::InProgress => "In progress",
        RunReportStatus::Completed => "Completed",
        RunReportStatus::Failed => "Failed",
        RunReportStatus::Cancelled => "Cancelled",
        RunReportStatus::Interrupted => "Interrupted",
        RunReportStatus::Blocked => "Blocked",
        RunReportStatus::CompletedWithReviewRequired => "Pending review",
        RunReportStatus::RecoveryReview => "Recovery Review required",
        RunReportStatus::ReviewCleared => "Review cleared",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MARKETING_PHRASES: [&str; 3] = ["in rhythm.", "A calmer way to", "WELCOME TO SYNCPLUS"];

    fn copy_avoids_marketing(text: &str) -> bool {
        MARKETING_PHRASES.iter().all(|phrase| {
            !text
                .to_ascii_lowercase()
                .contains(&phrase.to_ascii_lowercase())
        })
    }

    #[test]
    fn unselected_sidebar_items_share_muted_ink_and_selected_uses_copper() {
        let items = sidebar_items(ChromeSurface::Profiles);
        let labels: Vec<_> = items.iter().map(|item| item.label).collect();
        assert_eq!(
            labels,
            [
                "Overview",
                "Profiles",
                "Sync workspace",
                "Run Reports",
                "Settings",
                "Help & Support",
            ]
        );
        assert!(items.iter().all(|item| item.label != "Recovery Review"));
        for item in &items {
            if item.selected {
                assert_eq!(item.surface, ChromeSurface::Profiles);
                assert_eq!(item.accent, ChromeAccent::Copper);
            } else {
                assert_eq!(item.accent, ChromeAccent::Muted);
            }
        }
        assert_eq!(items.iter().filter(|item| item.selected).count(), 1);
    }

    #[test]
    fn settings_is_a_main_chrome_destination() {
        let items = sidebar_items(ChromeSurface::Settings);
        let settings = items
            .iter()
            .find(|item| item.surface == ChromeSurface::Settings)
            .expect("Settings");
        assert_eq!(settings.label, "Settings");
        assert!(settings.selected);
        assert_eq!(settings.accent, ChromeAccent::Copper);
    }

    #[test]
    fn recovery_review_surfaces_as_notice_not_permanent_nav() {
        let items = sidebar_items(ChromeSurface::Reports);
        assert!(items.iter().all(|item| item.label != "Recovery Review"));
        assert_eq!(recovery_review_notice(false), None);
        assert_eq!(recovery_review_notice(true), Some(RECOVERY_REVIEW_NOTICE));
        assert_eq!(reports_badge(false), None);
        assert_eq!(reports_badge(true), Some(REPORTS_REVIEW_BADGE));
        assert!(recovery_review_is_pending([
            RunReportStatus::Completed,
            RunReportStatus::RecoveryReview
        ]));
        assert!(!recovery_review_is_pending([
            RunReportStatus::Completed,
            RunReportStatus::ReviewCleared
        ]));
        assert!(status_requires_recovery_review(
            RunReportStatus::Interrupted
        ));
        assert!(!status_requires_recovery_review(
            RunReportStatus::CompletedWithReviewRequired
        ));
        assert!(status_requires_report_review(
            RunReportStatus::CompletedWithReviewRequired
        ));
        assert!(report_review_is_pending([
            RunReportStatus::CompletedWithReviewRequired
        ]));
    }

    #[test]
    fn empty_overview_is_calm_first_run_with_one_primary_action() {
        let overview = empty_overview();
        assert_eq!(overview.eyebrow, EMPTY_OVERVIEW_EYEBROW);
        assert_eq!(overview.title, EMPTY_OVERVIEW_TITLE);
        assert_eq!(overview.primary_action, OverviewAction::CreateProfile);
        assert_eq!(overview.primary_action.label(), EMPTY_OVERVIEW_PRIMARY);
        assert_eq!(overview.last_run, NO_SYNC_RUN_YET);
        assert!(overview.body.contains("confirmation"));
        assert!(copy_avoids_marketing(&overview.title));
        assert!(copy_avoids_marketing(&overview.body));
        assert!(copy_avoids_marketing(overview.primary_action.label()));
    }

    #[test]
    fn populated_overview_shows_profile_last_run_and_next_safe_action() {
        let overview = populated_overview(
            "Documents backup",
            "One-Way Sync",
            Some(RunReportStatus::Completed),
            false,
        );
        assert_eq!(overview.eyebrow, POPULATED_OVERVIEW_EYEBROW);
        assert_eq!(overview.title, "Documents backup");
        assert!(overview.body.contains("One-Way Sync"));
        assert!(overview.body.contains("Last Sync Run · Completed"));
        assert_eq!(overview.last_run, "Last Sync Run · Completed");
        assert_eq!(overview.next_safe_action, NEXT_ACTION_REVIEW_PLAN);
        assert_eq!(overview.primary_action, OverviewAction::Synchronise);
        assert!(overview.recovery_notice.is_none());
        assert!(copy_avoids_marketing(&overview.title));
        assert!(copy_avoids_marketing(&overview.body));

        let recovery = populated_overview(
            "Documents backup",
            "One-Way Sync",
            Some(RunReportStatus::RecoveryReview),
            true,
        );
        assert_eq!(recovery.next_safe_action, NEXT_ACTION_RECOVERY_REVIEW);
        assert_eq!(recovery.primary_action, OverviewAction::OpenRecoveryReview);
        assert_eq!(recovery.recovery_notice, Some(RECOVERY_REVIEW_NOTICE));
        assert_eq!(
            recovery.last_run,
            "Last Sync Run · Recovery Review required"
        );
        assert_eq!(last_run_label(None), NO_SYNC_RUN_YET);
    }

    #[test]
    fn wizard_upcoming_steps_are_not_warnings() {
        assert_eq!(wizard_step_caption(true, false), "Current step");
        assert_eq!(wizard_step_caption(false, true), "Complete");
        assert_eq!(wizard_step_caption(false, false), "Upcoming");
        assert_ne!(wizard_step_caption(false, false), "Required");
    }
}
