use eframe::egui;

/// Desktop Brand Theme tokens. SyncPlus uses one blue-and-white appearance.
///
/// Colours live only in the GUI. Core may still persist a named preference;
/// the desktop chrome does not switch skins from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrandTheme {
    pub canvas: egui::Color32,
    pub on_canvas: egui::Color32,
    pub on_canvas_muted: egui::Color32,
    pub surface: egui::Color32,
    pub elevated: egui::Color32,
    pub field: egui::Color32,
    pub text: egui::Color32,
    pub muted: egui::Color32,
    pub border: egui::Color32,
    pub border_subtle: egui::Color32,
    pub copper: egui::Color32,
    pub on_copper: egui::Color32,
    pub copper_soft: egui::Color32,
    pub steel: egui::Color32,
    pub on_steel: egui::Color32,
    pub steel_soft: egui::Color32,
    pub danger: egui::Color32,
    pub on_danger: egui::Color32,
    pub danger_soft: egui::Color32,
    pub on_danger_soft: egui::Color32,
    pub warning: egui::Color32,
    pub on_warning: egui::Color32,
    pub warning_soft: egui::Color32,
    pub on_warning_soft: egui::Color32,
    pub success: egui::Color32,
    pub on_success: egui::Color32,
    pub success_soft: egui::Color32,
    pub on_success_soft: egui::Color32,
}

const fn rgb(red: u8, green: u8, blue: u8) -> egui::Color32 {
    egui::Color32::from_rgb(red, green, blue)
}

/// Type roles for the desktop instrument. Titles stay in a tool range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeRole {
    Eyebrow,
    Title,
    Body,
    Caption,
}

impl TypeRole {
    pub const fn size(self) -> f32 {
        match self {
            Self::Eyebrow | Self::Caption => 12.0,
            Self::Title => 20.0,
            Self::Body => 14.0,
        }
    }
}

/// Height of a single-line form field. egui has no Bootstrap sheet; this is
/// the shared field size, and [`singleline_edit`] centers the inner text.
pub const FIELD_HEIGHT: f32 = 36.0;

pub fn singleline_edit(text: &mut String) -> egui::TextEdit<'_> {
    egui::TextEdit::singleline(text)
        .vertical_align(egui::Align::Center)
        .min_size(egui::vec2(0.0, FIELD_HEIGHT))
}

pub fn add_singleline(ui: &mut egui::Ui, text: &mut String, width: f32) -> egui::Response {
    ui.add_sized(
        egui::vec2(width.max(0.0), FIELD_HEIGHT),
        singleline_edit(text),
    )
}

impl BrandTheme {
    /// Navy rail, white workspace, blue primary. Token names `copper` and
    /// `steel` remain the primary and companion accents.
    pub const fn desktop() -> Self {
        Self {
            canvas: rgb(0x0F, 0x3A, 0x6B),
            on_canvas: rgb(0xF4, 0xF8, 0xFC),
            on_canvas_muted: rgb(0xA9, 0xC4, 0xE0),
            surface: rgb(0xFF, 0xFF, 0xFF),
            elevated: rgb(0xF4, 0xF8, 0xFC),
            field: rgb(0xFF, 0xFF, 0xFF),
            text: rgb(0x1A, 0x24, 0x33),
            muted: rgb(0x4E, 0x62, 0x78),
            border: rgb(0xC5, 0xD4, 0xE4),
            border_subtle: rgb(0xE2, 0xEA, 0xF2),
            copper: rgb(0x15, 0x65, 0xC0),
            on_copper: rgb(0xFF, 0xFF, 0xFF),
            copper_soft: rgb(0xE3, 0xF0, 0xFC),
            steel: rgb(0x1E, 0x4E, 0x8C),
            on_steel: rgb(0xFF, 0xFF, 0xFF),
            steel_soft: rgb(0xD6, 0xE6, 0xF8),
            danger: rgb(0xC6, 0x28, 0x28),
            on_danger: rgb(0xFF, 0xFF, 0xFF),
            danger_soft: rgb(0xFC, 0xE8, 0xE8),
            on_danger_soft: rgb(0xB7, 0x1C, 0x1C),
            warning: rgb(0xB2, 0x6A, 0x00),
            on_warning: rgb(0xFF, 0xFF, 0xFF),
            warning_soft: rgb(0xFF, 0xF3, 0xD6),
            on_warning_soft: rgb(0x8A, 0x5A, 0x00),
            success: rgb(0x1B, 0x6E, 0x3A),
            on_success: rgb(0xFF, 0xFF, 0xFF),
            success_soft: rgb(0xE7, 0xF4, 0xEA),
            on_success_soft: rgb(0x18, 0x5C, 0x30),
        }
    }

    pub const fn dark() -> Self {
        Self::desktop()
    }

    pub const fn light() -> Self {
        Self::desktop()
    }

    pub const fn for_dark_mode(_dark_mode: bool) -> Self {
        Self::desktop()
    }

    pub fn from_ui(_ui: &egui::Ui) -> Self {
        Self::desktop()
    }

    pub const fn roles(self) -> [(&'static str, egui::Color32); 28] {
        [
            ("canvas", self.canvas),
            ("on_canvas", self.on_canvas),
            ("on_canvas_muted", self.on_canvas_muted),
            ("surface", self.surface),
            ("elevated", self.elevated),
            ("field", self.field),
            ("text", self.text),
            ("muted", self.muted),
            ("border", self.border),
            ("border_subtle", self.border_subtle),
            ("copper", self.copper),
            ("on_copper", self.on_copper),
            ("copper_soft", self.copper_soft),
            ("steel", self.steel),
            ("on_steel", self.on_steel),
            ("steel_soft", self.steel_soft),
            ("danger", self.danger),
            ("on_danger", self.on_danger),
            ("danger_soft", self.danger_soft),
            ("on_danger_soft", self.on_danger_soft),
            ("warning", self.warning),
            ("on_warning", self.on_warning),
            ("warning_soft", self.warning_soft),
            ("on_warning_soft", self.on_warning_soft),
            ("success", self.success),
            ("on_success", self.on_success),
            ("success_soft", self.success_soft),
            ("on_success_soft", self.on_success_soft),
        ]
    }

    pub fn apply_to_style(self, style: &mut egui::Style) {
        style.visuals.dark_mode = false;
        style.visuals.button_frame = true;
        style.visuals.override_text_color = Some(self.text);
        style.visuals.weak_text_color = Some(self.muted);
        style.visuals.selection.bg_fill = self.copper_soft;
        style.visuals.selection.stroke = egui::Stroke::new(1.0, self.copper);
        style.visuals.hyperlink_color = self.steel;
        style.visuals.warn_fg_color = self.warning;
        style.visuals.error_fg_color = self.danger;
        style.visuals.faint_bg_color = self.elevated;
        style.visuals.panel_fill = self.surface;
        style.visuals.window_fill = self.surface;
        style.visuals.extreme_bg_color = self.field;
        style.visuals.text_edit_bg_color = Some(self.field);
        style.visuals.window_corner_radius = egui::CornerRadius::same(14);
        style.visuals.menu_corner_radius = egui::CornerRadius::same(10);
        style.visuals.widgets.noninteractive.bg_fill = self.surface;
        style.visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, self.border_subtle);
        style.visuals.widgets.inactive.bg_fill = self.elevated;
        style.visuals.widgets.inactive.weak_bg_fill = self.elevated;
        style.visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, self.border);
        style.visuals.widgets.hovered.bg_fill = self.copper_soft;
        style.visuals.widgets.hovered.weak_bg_fill = self.copper_soft;
        style.visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, self.copper);
        style.visuals.widgets.active.bg_fill = self.copper_soft;
        style.visuals.widgets.active.weak_bg_fill = self.copper_soft;
        style.visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0, self.copper);
        style.visuals.widgets.open.bg_fill = self.copper_soft;
        style.visuals.widgets.open.weak_bg_fill = self.copper_soft;
        style.visuals.widgets.open.bg_stroke = egui::Stroke::new(1.0, self.copper);
        style.visuals.widgets.noninteractive.corner_radius = egui::CornerRadius::same(8);
        style.visuals.widgets.inactive.corner_radius = egui::CornerRadius::same(8);
        style.visuals.widgets.hovered.corner_radius = egui::CornerRadius::same(8);
        style.visuals.widgets.active.corner_radius = egui::CornerRadius::same(8);
        style.visuals.widgets.open.corner_radius = egui::CornerRadius::same(8);
        style.spacing.interact_size.y = FIELD_HEIGHT;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relative_luminance(color: egui::Color32) -> f32 {
        fn linear_channel(channel: u8) -> f32 {
            let channel = f32::from(channel) / 255.0;
            if channel <= 0.04045 {
                channel / 12.92
            } else {
                ((channel + 0.055) / 1.055).powf(2.4)
            }
        }

        0.2126 * linear_channel(color.r())
            + 0.7152 * linear_channel(color.g())
            + 0.0722 * linear_channel(color.b())
    }

    fn contrast_ratio(foreground: egui::Color32, background: egui::Color32) -> f32 {
        let foreground = relative_luminance(foreground);
        let background = relative_luminance(background);
        (foreground.max(background) + 0.05) / (foreground.min(background) + 0.05)
    }

    #[test]
    fn desktop_appearance_is_navy_rail_white_workspace_and_blue_accent() {
        let theme = BrandTheme::desktop();
        assert_eq!(theme.canvas, rgb(0x0F, 0x3A, 0x6B));
        assert_eq!(theme.surface, rgb(0xFF, 0xFF, 0xFF));
        assert_eq!(theme.field, rgb(0xFF, 0xFF, 0xFF));
        assert_eq!(theme.copper, rgb(0x15, 0x65, 0xC0));
        assert_eq!(theme.steel, rgb(0x1E, 0x4E, 0x8C));
        assert_eq!(BrandTheme::dark(), theme);
        assert_eq!(BrandTheme::light(), theme);
        assert_eq!(BrandTheme::for_dark_mode(true), theme);
        assert_eq!(BrandTheme::for_dark_mode(false), theme);
    }

    #[test]
    fn desktop_exposes_the_full_token_role_set() {
        let roles: Vec<&str> = BrandTheme::desktop()
            .roles()
            .into_iter()
            .map(|(role, _)| role)
            .collect();
        for required in [
            "canvas",
            "on_canvas",
            "on_canvas_muted",
            "surface",
            "elevated",
            "field",
            "text",
            "muted",
            "border",
            "copper",
            "on_copper",
            "copper_soft",
            "steel",
            "on_steel",
            "steel_soft",
            "danger",
            "on_danger",
            "danger_soft",
            "on_danger_soft",
            "warning",
            "on_warning",
            "warning_soft",
            "success",
            "on_success",
            "success_soft",
            "on_success_soft",
        ] {
            assert!(
                roles.contains(&required),
                "desktop appearance is missing token role {required}"
            );
        }
    }

    #[test]
    fn copper_steel_danger_and_warning_are_distinct() {
        let theme = BrandTheme::desktop();
        let accents = [theme.copper, theme.steel, theme.danger, theme.warning];
        for (index, color) in accents.iter().enumerate() {
            for other in accents.iter().skip(index + 1) {
                assert_ne!(
                    color, other,
                    "primary, companion, danger, and warning must stay distinct"
                );
            }
        }
    }

    #[test]
    fn forbidden_magenta_mint_and_teal_are_absent_from_token_roles() {
        let magenta = rgb(0xFF, 0x00, 0x99);
        let neon_mint = rgb(0x00, 0xFF, 0x85);
        let teal = rgb(0x79, 0xD2, 0xC3);
        for (role, color) in BrandTheme::desktop().roles() {
            assert_ne!(color, magenta, "{role} must not be magenta");
            assert_ne!(color, neon_mint, "{role} must not be neon mint");
            assert_ne!(color, teal, "{role} must not be teal");
        }
    }

    #[test]
    fn body_muted_on_accent_and_rail_text_meet_contrast() {
        let theme = BrandTheme::desktop();
        for (label, foreground, background) in [
            ("body on surface", theme.text, theme.surface),
            ("muted on surface", theme.muted, theme.surface),
            ("on-accent on copper", theme.on_copper, theme.copper),
            ("danger-on-soft", theme.on_danger_soft, theme.danger_soft),
            ("success-on-soft", theme.on_success_soft, theme.success_soft),
            ("on-canvas on rail", theme.on_canvas, theme.canvas),
            (
                "on-canvas-muted on rail",
                theme.on_canvas_muted,
                theme.canvas,
            ),
            ("on-success on success", theme.on_success, theme.success),
        ] {
            assert!(
                contrast_ratio(foreground, background) >= 4.5,
                "{label} must meet 4.5:1, got {:.2}",
                contrast_ratio(foreground, background)
            );
        }
    }

    #[test]
    fn applying_the_theme_paints_window_chrome_from_tokens() {
        let theme = BrandTheme::desktop();
        let mut style = egui::Style::default();
        theme.apply_to_style(&mut style);
        assert!(!style.visuals.dark_mode);
        assert_eq!(style.visuals.panel_fill, theme.surface);
        assert_eq!(style.visuals.window_fill, theme.surface);
        assert_eq!(style.visuals.extreme_bg_color, theme.field);
        assert_eq!(style.visuals.selection.bg_fill, theme.copper_soft);
        assert_eq!(style.visuals.selection.stroke.color, theme.copper);
        assert_eq!(style.visuals.hyperlink_color, theme.steel);
        assert_eq!(style.visuals.warn_fg_color, theme.warning);
        assert_eq!(style.visuals.error_fg_color, theme.danger);
        assert_eq!(style.visuals.widgets.hovered.bg_stroke.color, theme.copper);
        assert_eq!(style.spacing.interact_size.y, FIELD_HEIGHT);
    }

    #[test]
    fn type_roles_are_eyebrow_title_body_and_caption_in_a_tool_range() {
        assert_eq!(TypeRole::Eyebrow.size(), 12.0);
        assert_eq!(TypeRole::Title.size(), 20.0);
        assert_eq!(TypeRole::Body.size(), 14.0);
        assert_eq!(TypeRole::Caption.size(), 12.0);
        assert!(TypeRole::Title.size() <= 24.0);
        assert!(TypeRole::Title.size() < 38.0);
        assert!(TypeRole::Title.size() < 46.0);
    }
}
