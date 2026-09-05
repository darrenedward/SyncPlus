pub const ONE_WAY_TITLE: &str = "One-Way Sync";
pub const ONE_WAY_CAPTION: &str = "Copy the source folder into the destination. The source stays unless you later enable Safe Delete.";
pub const MIRROR_TITLE: &str = "Mirror Sync";
pub const MIRROR_CAPTION: &str =
    "Review both folders independently. Neither side wins until you confirm each conflict.";

#[cfg(test)]
mod tests {
    use super::{MIRROR_TITLE, ONE_WAY_TITLE};

    #[test]
    fn setup_cards_use_syncplus_mode_names_not_aomei_labels() {
        assert_eq!(ONE_WAY_TITLE, "One-Way Sync");
        assert_eq!(MIRROR_TITLE, "Mirror Sync");
        assert_ne!(ONE_WAY_TITLE, "Basic Sync");
        assert_ne!(MIRROR_TITLE, "Two-Way Sync");
        assert_ne!(MIRROR_TITLE, "Real-Time Sync");
    }
}
