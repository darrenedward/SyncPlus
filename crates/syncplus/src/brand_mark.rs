//! Brand Mark assets shared by the packaged desktop icon and the window icon.

const WINDOW_ICON_PNG: &[u8] =
    include_bytes!("../../../packaging/icons/hicolor/256x256/apps/syncplus.png");

/// Window icon decoded from the packaged 256px Brand Mark PNG.
pub fn window_icon() -> eframe::egui::IconData {
    eframe::icon_data::from_png_bytes(WINDOW_ICON_PNG)
        .expect("Brand Mark window icon PNG must decode")
}

#[cfg(test)]
fn packaging_icons_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packaging/icons")
}

#[cfg(test)]
mod tests {
    use super::packaging_icons_dir;

    const FORBIDDEN_HUES: [&str; 3] = ["#FF0099", "#00FF85", "#79D2C3"];
    const SECRET_NEEDLES: [&str; 6] = [
        "PRIVATE KEY",
        "BEGIN OPENSSH",
        "passphrase",
        "password=",
        "DRAGNET",
        "/home/",
    ];
    const REQUIRED_DESKTOP_ICON_SIZES: [u32; 9] = [16, 22, 24, 32, 48, 64, 128, 256, 512];

    fn read_icon(name: &str) -> String {
        std::fs::read_to_string(packaging_icons_dir().join(name)).unwrap_or_else(|error| {
            panic!("Brand Mark asset {name} must exist: {error}");
        })
    }

    fn assert_no_forbidden_hues(label: &str, svg: &str) {
        let lowered = svg.to_ascii_lowercase();
        for hue in FORBIDDEN_HUES {
            assert!(
                !lowered.contains(&hue.to_ascii_lowercase()),
                "{label} must not contain forbidden hue {hue}"
            );
        }
    }

    fn assert_no_secrets(label: &str, body: &str) {
        for needle in SECRET_NEEDLES {
            assert!(
                !body.contains(needle),
                "{label} must not contain secret or machine-path needle {needle}"
            );
        }
    }

    #[test]
    fn dark_brand_mark_is_copper_outbound_and_steel_inbound_on_a_rounded_square() {
        let svg = read_icon("syncplus.svg");
        assert!(
            svg.contains("rx=\"14\""),
            "dark Brand Mark must be a rounded square"
        );
        assert!(
            svg.contains("#141210"),
            "dark Brand Mark must sit on warm ink"
        );
        assert!(
            svg.contains("d=\"M18 27a16 16 0 0 1 27-8l4 4\" fill=\"none\" stroke=\"#E08A3C\""),
            "dark Brand Mark must stroke the outbound arrow in copper"
        );
        assert!(
            svg.contains("d=\"M46 37a16 16 0 0 1-27 8l-4-4\" fill=\"none\" stroke=\"#8AA0B8\""),
            "dark Brand Mark must stroke the inbound arrow in steel"
        );
        assert_no_forbidden_hues("dark Brand Mark", &svg);
        assert_no_secrets("dark Brand Mark", &svg);
    }

    #[test]
    fn light_brand_mark_remains_legible_on_warm_paper() {
        let svg = read_icon("syncplus-light.svg");
        assert!(
            svg.contains("rx=\"14\""),
            "light Brand Mark must be a rounded square"
        );
        assert!(
            svg.contains("#F7F0E4"),
            "light Brand Mark must sit on warm paper"
        );
        assert!(
            svg.contains("d=\"M18 27a16 16 0 0 1 27-8l4 4\" fill=\"none\" stroke=\"#B65E1C\""),
            "light Brand Mark must stroke the outbound arrow in copper"
        );
        assert!(
            svg.contains("d=\"M46 37a16 16 0 0 1-27 8l-4-4\" fill=\"none\" stroke=\"#3E5874\""),
            "light Brand Mark must stroke the inbound arrow in steel"
        );
        assert_no_forbidden_hues("light Brand Mark", &svg);
        assert_no_secrets("light Brand Mark", &svg);
    }

    #[test]
    fn monochrome_brand_mark_exists_for_constrained_backgrounds() {
        let svg = read_icon("syncplus-symbolic.svg");
        assert!(
            svg.contains("currentColor") || svg.contains("#1C1712"),
            "monochrome Brand Mark must use ink or currentColor"
        );
        assert!(
            !svg.contains("#141210") || svg.contains("fill=\"none\""),
            "monochrome Brand Mark must not require a warm-ink plate"
        );
        assert_no_forbidden_hues("monochrome Brand Mark", &svg);
        assert_no_secrets("monochrome Brand Mark", &svg);
    }

    #[test]
    fn required_desktop_icon_sizes_are_produced_from_the_dark_brand_mark() {
        for size in REQUIRED_DESKTOP_ICON_SIZES {
            let path =
                packaging_icons_dir().join(format!("hicolor/{size}x{size}/apps/syncplus.png"));
            let bytes = std::fs::read(&path).unwrap_or_else(|error| {
                panic!("desktop icon {path:?} must exist: {error}");
            });
            let icon = eframe::icon_data::from_png_bytes(&bytes)
                .unwrap_or_else(|error| panic!("desktop icon {path:?} must be a PNG: {error}"));
            assert_eq!(icon.width, size, "desktop icon width for {size}px");
            assert_eq!(icon.height, size, "desktop icon height for {size}px");
        }
    }

    fn opaque_pixels_near(rgba: &[u8], target: [u8; 3], max_distance: i32) -> bool {
        rgba.chunks_exact(4).any(|pixel| {
            if pixel[3] < 200 {
                return false;
            }
            let distance = (i32::from(pixel[0]) - i32::from(target[0])).pow(2)
                + (i32::from(pixel[1]) - i32::from(target[1])).pow(2)
                + (i32::from(pixel[2]) - i32::from(target[2])).pow(2);
            distance <= max_distance.pow(2)
        })
    }

    #[test]
    fn packaged_256_brand_mark_contains_copper_and_steel_not_forbidden_hues() {
        let path = packaging_icons_dir().join("hicolor/256x256/apps/syncplus.png");
        let bytes = std::fs::read(&path).unwrap();
        let icon = eframe::icon_data::from_png_bytes(&bytes).unwrap();
        assert!(
            opaque_pixels_near(&icon.rgba, [20, 18, 16], 12),
            "256 Brand Mark must include the warm-ink plate"
        );
        assert!(
            opaque_pixels_near(&icon.rgba, [224, 138, 60], 28),
            "256 Brand Mark must include copper outbound pixels"
        );
        assert!(
            opaque_pixels_near(&icon.rgba, [138, 160, 184], 28),
            "256 Brand Mark must include steel inbound pixels"
        );
        assert!(
            !opaque_pixels_near(&icon.rgba, [255, 0, 153], 20),
            "256 Brand Mark must not contain magenta"
        );
        assert!(
            !opaque_pixels_near(&icon.rgba, [0, 255, 133], 20),
            "256 Brand Mark must not contain neon mint"
        );
        assert!(
            !opaque_pixels_near(&icon.rgba, [121, 210, 195], 20),
            "256 Brand Mark must not contain teal"
        );
    }

    #[test]
    fn window_icon_loads_the_packaged_brand_mark_png() {
        let packaged =
            std::fs::read(packaging_icons_dir().join("hicolor/256x256/apps/syncplus.png")).unwrap();
        let from_package = eframe::icon_data::from_png_bytes(&packaged).unwrap();
        let icon = super::window_icon();
        assert_eq!(icon.width, 256);
        assert_eq!(icon.height, 256);
        assert_eq!(icon.rgba, from_package.rgba);
        assert!(
            opaque_pixels_near(&icon.rgba, [224, 138, 60], 28),
            "window icon must show copper outbound"
        );
        assert!(
            opaque_pixels_near(&icon.rgba, [138, 160, 184], 28),
            "window icon must show steel inbound"
        );
    }
}
