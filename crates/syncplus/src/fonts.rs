use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

use eframe::egui;

static REGULAR_SANS_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Regular-weight system sans faces. egui's bundled proportional face is Ubuntu Light.
const REGULAR_SANS_CANDIDATES: &[&str] = &[
    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/ubuntu/Ubuntu-R.ttf",
    "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
];

pub fn preferred_regular_sans_path() -> Option<PathBuf> {
    REGULAR_SANS_CANDIDATES
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
}

pub fn install_regular_sans(context: &egui::Context) {
    if REGULAR_SANS_INSTALLED.swap(true, Ordering::Relaxed) {
        return;
    }
    let Some(path) = preferred_regular_sans_path() else {
        return;
    };
    let Ok(bytes) = std::fs::read(&path) else {
        return;
    };
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "syncplus-sans".to_owned(),
        std::sync::Arc::new(egui::FontData::from_owned(bytes)),
    );
    if let Some(proportional) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
        proportional.insert(0, "syncplus-sans".to_owned());
    }
    context.set_fonts(fonts);
}

#[cfg(test)]
fn candidate_is_regular_weight(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    !name.contains("light") && !name.contains("thin")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proportional_font_candidates_are_regular_weight_not_light() {
        for candidate in REGULAR_SANS_CANDIDATES {
            assert!(
                candidate_is_regular_weight(Path::new(candidate)),
                "{candidate} must be a regular-weight face, not Light"
            );
        }
        if let Some(path) = preferred_regular_sans_path() {
            assert!(candidate_is_regular_weight(&path));
        }
    }
}
