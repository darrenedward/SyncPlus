use eframe::egui;

/// Desktop Brand Theme tokens for Dark Appearance and Light Appearance.
///
/// Colours live only in the GUI. Core persists `ThemePreference` names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BrandTheme {
    pub canvas: egui::Color32,
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
}

const fn rgb(red: u8, green: u8, blue: u8) -> egui::Color32 {
    egui::Color32::from_rgb(red, green, blue)
}

impl BrandTheme {
    /// Warm-ink Dark Appearance. Canvas is not pure black.
    pub const fn dark() -> Self {
        Self {
            canvas: rgb(0x14, 0x12, 0x10),
            surface: rgb(0x1C, 0x19, 0x16),
            elevated: rgb(0x26, 0x22, 0x1D),
            field: rgb(0x12, 0x10, 0x0E),
            text: rgb(0xF3, 0xED, 0xE4),
            muted: rgb(0xB5, 0xA9, 0x9A),
            border: rgb(0x6F, 0x64, 0x58),
            border_subtle: rgb(0x4F, 0x46, 0x3E),
            copper: rgb(0xE0, 0x8A, 0x3C),
            on_copper: rgb(0x1A, 0x12, 0x08),
            copper_soft: rgb(0x3A, 0x24, 0x14),
            steel: rgb(0x8A, 0xA0, 0xB8),
            on_steel: rgb(0x1A, 0x12, 0x08),
            steel_soft: rgb(0x24, 0x30, 0x40),
            danger: rgb(0xD3, 0x5A, 0x5A),
            on_danger: rgb(0x1A, 0x12, 0x08),
            danger_soft: rgb(0x3A, 0x1C, 0x1C),
            // Spec danger on danger-soft is below 4.5:1; body ink on the soft
            // fill is the danger-on-soft text role.
            on_danger_soft: rgb(0xF3, 0xED, 0xE4),
            warning: rgb(0xE0, 0xB2, 0x4A),
            on_warning: rgb(0x1A, 0x12, 0x08),
            warning_soft: rgb(0x3A, 0x30, 0x14),
            on_warning_soft: rgb(0xF3, 0xED, 0xE4),
        }
    }

    /// Warm-paper Light Appearance. Canvas is not white.
    pub const fn light() -> Self {
        Self {
            canvas: rgb(0xEF, 0xE6, 0xD8),
            surface: rgb(0xF7, 0xF0, 0xE4),
            elevated: rgb(0xE7, 0xDC, 0xCB),
            field: rgb(0xFF, 0xF8, 0xEE),
            text: rgb(0x1C, 0x17, 0x12),
            muted: rgb(0x6B, 0x5E, 0x50),
            border: rgb(0xC4, 0xB6, 0xA4),
            border_subtle: rgb(0xD8, 0xCB, 0xB8),
            // Spec copper #B65E1C is 4.32:1 on #FFF8EE; darkened to hold 4.5:1.
            copper: rgb(0xB0, 0x56, 0x18),
            on_copper: rgb(0xFF, 0xF8, 0xEE),
            copper_soft: rgb(0xF3, 0xD7, 0xBE),
            steel: rgb(0x3E, 0x58, 0x74),
            on_steel: rgb(0xFF, 0xF8, 0xEE),
            steel_soft: rgb(0xD5, 0xDE, 0xE8),
            danger: rgb(0xB4, 0x23, 0x32),
            on_danger: rgb(0xFF, 0xF8, 0xEE),
            danger_soft: rgb(0xF7, 0xD7, 0xDA),
            on_danger_soft: rgb(0xB4, 0x23, 0x32),
            warning: rgb(0x8A, 0x5A, 0x12),
            on_warning: rgb(0xFF, 0xF8, 0xEE),
            warning_soft: rgb(0xF3, 0xE6, 0xC4),
            on_warning_soft: rgb(0x8A, 0x5A, 0x12),
        }
    }

    pub const fn for_dark_mode(dark_mode: bool) -> Self {
        if dark_mode {
            Self::dark()
        } else {
            Self::light()
        }
    }

    pub fn from_ui(ui: &egui::Ui) -> Self {
        Self::for_dark_mode(ui.visuals().dark_mode)
    }

    pub const fn roles(self) -> [(&'static str, egui::Color32); 22] {
        [
            ("canvas", self.canvas),
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
        ]
    }

    pub fn apply_to_style(self, style: &mut egui::Style) {
        style.visuals.button_frame = true;
        style.visuals.override_text_color = Some(self.text);
        style.visuals.weak_text_color = Some(self.muted);
        style.visuals.selection.bg_fill = self.copper_soft;
        style.visuals.selection.stroke = egui::Stroke::new(1.0, self.copper);
        style.visuals.hyperlink_color = self.steel;
        style.visuals.warn_fg_color = self.warning;
        style.visuals.error_fg_color = self.danger;
        style.visuals.faint_bg_color = self.elevated;
        style.visuals.panel_fill = self.canvas;
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

    fn appearances() -> [(&'static str, BrandTheme); 2] {
        [("dark", BrandTheme::dark()), ("light", BrandTheme::light())]
    }

    #[test]
    fn both_appearances_expose_the_full_token_role_set() {
        for (name, theme) in appearances() {
            let roles: Vec<&str> = theme.roles().into_iter().map(|(role, _)| role).collect();
            for required in [
                "canvas",
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
            ] {
                assert!(
                    roles.contains(&required),
                    "{name} appearance is missing token role {required}"
                );
            }
        }
    }

    #[test]
    fn dark_appearance_uses_warm_ink_not_black() {
        let dark = BrandTheme::dark();
        assert_ne!(dark.canvas, egui::Color32::BLACK);
        assert_eq!(dark.canvas, rgb(0x14, 0x12, 0x10));
        assert_eq!(dark.surface, rgb(0x1C, 0x19, 0x16));
        assert_eq!(dark.elevated, rgb(0x26, 0x22, 0x1D));
        assert_eq!(dark.field, rgb(0x12, 0x10, 0x0E));
        assert!(relative_luminance(dark.canvas) > relative_luminance(egui::Color32::BLACK));
    }

    #[test]
    fn light_appearance_uses_warm_paper_not_white() {
        let light = BrandTheme::light();
        assert_ne!(light.canvas, egui::Color32::WHITE);
        assert_ne!(light.surface, egui::Color32::WHITE);
        assert_eq!(light.canvas, rgb(0xEF, 0xE6, 0xD8));
        assert_eq!(light.surface, rgb(0xF7, 0xF0, 0xE4));
        assert_eq!(light.elevated, rgb(0xE7, 0xDC, 0xCB));
        assert_ne!(light.field, egui::Color32::WHITE);
    }

    #[test]
    fn copper_steel_danger_and_warning_are_distinct_in_both_appearances() {
        for (name, theme) in appearances() {
            let accents = [theme.copper, theme.steel, theme.danger, theme.warning];
            for (index, color) in accents.iter().enumerate() {
                for other in accents.iter().skip(index + 1) {
                    assert_ne!(
                        color, other,
                        "{name} copper, steel, danger, and warning must stay distinct"
                    );
                }
            }
        }
    }

    #[test]
    fn forbidden_magenta_mint_and_teal_are_absent_from_token_roles() {
        let magenta = rgb(0xFF, 0x00, 0x99);
        let neon_mint = rgb(0x00, 0xFF, 0x85);
        let teal = rgb(0x79, 0xD2, 0xC3);
        for (name, theme) in appearances() {
            for (role, color) in theme.roles() {
                assert_ne!(color, magenta, "{name} {role} must not be magenta");
                assert_ne!(color, neon_mint, "{name} {role} must not be neon mint");
                assert_ne!(color, teal, "{name} {role} must not be teal");
            }
        }
    }

    #[test]
    fn body_muted_on_accent_and_danger_on_soft_meet_contrast_in_both_appearances() {
        for (name, theme) in appearances() {
            for (label, foreground, background) in [
                ("body on canvas", theme.text, theme.canvas),
                ("body on surface", theme.text, theme.surface),
                ("muted on surface", theme.muted, theme.surface),
                ("on-accent on copper", theme.on_copper, theme.copper),
                ("danger-on-soft", theme.on_danger_soft, theme.danger_soft),
            ] {
                assert!(
                    contrast_ratio(foreground, background) >= 4.5,
                    "{name} {label} must meet 4.5:1, got {:.2}",
                    contrast_ratio(foreground, background)
                );
            }
        }
    }

    #[test]
    fn applying_a_theme_paints_window_chrome_from_tokens() {
        for theme in [BrandTheme::dark(), BrandTheme::light()] {
            let mut style = egui::Style::default();
            theme.apply_to_style(&mut style);
            assert_eq!(style.visuals.panel_fill, theme.canvas);
            assert_eq!(style.visuals.window_fill, theme.surface);
            assert_eq!(style.visuals.extreme_bg_color, theme.field);
            assert_eq!(style.visuals.selection.bg_fill, theme.copper_soft);
            assert_eq!(style.visuals.selection.stroke.color, theme.copper);
            assert_eq!(style.visuals.hyperlink_color, theme.steel);
            assert_eq!(style.visuals.warn_fg_color, theme.warning);
            assert_eq!(style.visuals.error_fg_color, theme.danger);
            assert_eq!(style.visuals.widgets.hovered.bg_stroke.color, theme.copper);
        }
    }

    #[test]
    fn dark_and_light_token_sets_are_not_the_same_skin() {
        let dark = BrandTheme::dark();
        let light = BrandTheme::light();
        assert_ne!(dark.canvas, light.canvas);
        assert_ne!(dark.copper, light.copper);
        assert_ne!(dark.steel, light.steel);
        assert!(relative_luminance(light.canvas) > relative_luminance(dark.canvas));
    }
}
