//! Public Brand Kit contracts for GitHub and Facebook identity assets.

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    const PROMISE: &str =
        "Review the plan. Confirm what changes. Uncertainty preserves the source.";
    const FORBIDDEN_HUES: [&str; 3] = ["#FF0099", "#00FF85", "#79D2C3"];
    const SECRET_NEEDLES: [&str; 8] = [
        "PRIVATE KEY",
        "BEGIN OPENSSH",
        "passphrase",
        "password=",
        "private-key",
        "file-content",
        "DRAGNET",
        "/home/",
    ];
    const REQUIRED_RELATIVE_PATHS: [&str; 18] = [
        "README.md",
        "mark/syncplus.svg",
        "mark/syncplus-light.svg",
        "mark/syncplus-mono.svg",
        "wordmark/wordmark-dark.svg",
        "wordmark/wordmark-light.svg",
        "wordmark/wordmark-mono.svg",
        "lockup/lockup-dark.svg",
        "lockup/lockup-light.svg",
        "lockup/lockup-mono.svg",
        "github/avatar.png",
        "github/social-preview-1280x640.png",
        "github/social-preview-1280x640.svg",
        "facebook/profile.png",
        "facebook/cover-1640x924.png",
        "facebook/cover-1640x924.svg",
        "facebook/post-1200x630.png",
        "facebook/post-1200x630.svg",
    ];

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn brand_dir() -> PathBuf {
        repo_root().join("docs/brand")
    }

    fn read_text(path: &Path) -> String {
        fs::read_to_string(path).unwrap_or_else(|error| {
            panic!("Brand Kit file {} must exist: {error}", path.display());
        })
    }

    fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries = fs::read_dir(dir).unwrap_or_else(|error| {
            panic!("Brand Kit directory {} must exist: {error}", dir.display());
        });
        for entry in entries {
            let path = entry.expect("Brand Kit directory entry").path();
            if path.is_dir() {
                collect_files(&path, out);
            } else {
                out.push(path);
            }
        }
    }

    fn png_dimensions(bytes: &[u8]) -> (u32, u32) {
        assert!(
            bytes.len() >= 24 && bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
            "Brand Kit raster must be a PNG"
        );
        let width = u32::from_be_bytes(bytes[16..20].try_into().expect("PNG width"));
        let height = u32::from_be_bytes(bytes[20..24].try_into().expect("PNG height"));
        (width, height)
    }

    fn assert_no_forbidden_hues(label: &str, body: &str) {
        let lowered = body.to_ascii_lowercase();
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
                "{label} must not contain secret or file-content needle {needle}"
            );
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
    fn required_brand_kit_files_exist() {
        for relative in REQUIRED_RELATIVE_PATHS {
            let path = brand_dir().join(relative);
            assert!(
                path.is_file(),
                "Brand Kit must contain {relative} at {}",
                path.display()
            );
        }
    }

    #[test]
    fn mark_wordmark_lockup_and_monochrome_variants_are_derived_from_the_brand_mark() {
        let brand = brand_dir();
        let icons = repo_root().join("packaging/icons");
        assert_eq!(
            read_text(&brand.join("mark/syncplus.svg")),
            read_text(&icons.join("syncplus.svg")),
            "kit dark mark must match the packaged Brand Mark"
        );
        assert_eq!(
            read_text(&brand.join("mark/syncplus-light.svg")),
            read_text(&icons.join("syncplus-light.svg")),
            "kit light mark must match the packaged light Brand Mark"
        );
        assert_eq!(
            read_text(&brand.join("mark/syncplus-mono.svg")),
            read_text(&icons.join("syncplus-symbolic.svg")),
            "kit monochrome mark must match the packaged symbolic Brand Mark"
        );

        let dark_lockup = read_text(&brand.join("lockup/lockup-dark.svg"));
        let light_lockup = read_text(&brand.join("lockup/lockup-light.svg"));
        let mono_lockup = read_text(&brand.join("lockup/lockup-mono.svg"));
        for (label, body) in [
            ("dark lockup", dark_lockup.as_str()),
            ("light lockup", light_lockup.as_str()),
            ("mono lockup", mono_lockup.as_str()),
        ] {
            assert!(
                body.contains("M18 27a16 16 0 0 1 27-8l4 4"),
                "{label} must include the outbound Brand Mark arrow"
            );
            assert!(
                body.contains("M46 37a16 16 0 0 1-27 8l-4-4"),
                "{label} must include the inbound Brand Mark arrow"
            );
            assert!(
                body.contains("SyncPlus"),
                "{label} must include the SyncPlus wordmark"
            );
        }

        let dark_wordmark = read_text(&brand.join("wordmark/wordmark-dark.svg"));
        let light_wordmark = read_text(&brand.join("wordmark/wordmark-light.svg"));
        assert!(
            dark_wordmark.contains("SyncPlus") && dark_wordmark.contains("#E08A3C"),
            "dark wordmark must be copper SyncPlus"
        );
        assert!(
            light_wordmark.contains("SyncPlus") && light_wordmark.contains("#141210"),
            "light wordmark must be ink SyncPlus"
        );
        assert!(
            read_text(&brand.join("wordmark/wordmark-mono.svg")).contains("SyncPlus"),
            "monochrome wordmark must spell SyncPlus"
        );
        assert!(
            dark_lockup.contains("#141210") && dark_lockup.contains("#E08A3C"),
            "Dark Appearance lockup must sit on warm ink with copper"
        );
        assert!(
            light_lockup.contains("#F7F0E4") && light_lockup.contains("#141210"),
            "Light Appearance lockup must sit on warm paper with ink"
        );
        assert!(
            mono_lockup.contains("currentColor") || mono_lockup.contains("#1C1712"),
            "monochrome lockup must use ink or currentColor"
        );
    }

    #[test]
    fn github_and_facebook_rasters_have_documented_dimensions() {
        let cases = [
            ("github/avatar.png", 512, 512, true),
            ("github/social-preview-1280x640.png", 1280, 640, false),
            ("facebook/profile.png", 512, 512, true),
            ("facebook/cover-1640x924.png", 1640, 924, false),
            ("facebook/post-1200x630.png", 1200, 630, false),
        ];
        for (relative, width, height, square) in cases {
            let bytes = fs::read(brand_dir().join(relative)).unwrap_or_else(|error| {
                panic!("{relative} must exist: {error}");
            });
            let (actual_width, actual_height) = png_dimensions(&bytes);
            assert_eq!(actual_width, width, "{relative} width");
            assert_eq!(actual_height, height, "{relative} height");
            if square {
                assert_eq!(actual_width, actual_height, "{relative} must be square");
            }
        }
    }

    #[test]
    fn kit_documentation_and_svgs_state_the_public_promise() {
        let brand = brand_dir();
        let docs = read_text(&brand.join("README.md"));
        assert!(
            docs.contains(PROMISE),
            "Brand Kit documentation must state the public promise exactly"
        );
        for relative in [
            "github/social-preview-1280x640.svg",
            "facebook/cover-1640x924.svg",
            "facebook/post-1200x630.svg",
            "lockup/lockup-dark.svg",
            "lockup/lockup-light.svg",
        ] {
            let body = read_text(&brand.join(relative));
            assert!(
                body.contains(PROMISE),
                "{relative} must contain the public promise"
            );
        }
        let root_readme = read_text(&repo_root().join("README.md"));
        assert!(
            root_readme.contains(PROMISE),
            "repository README must state the public promise exactly"
        );
    }

    #[test]
    fn kit_documentation_states_clear_space_minimum_size_allowed_backgrounds_and_forbidden_treatments()
     {
        let docs = read_text(&brand_dir().join("README.md"));
        let lowered = docs.to_ascii_lowercase();
        for phrase in [
            "clear space",
            "minimum size",
            "allowed backgrounds",
            "forbidden treatments",
        ] {
            assert!(
                lowered.contains(phrase),
                "Brand Kit documentation must state {phrase}"
            );
        }
        assert!(
            lowered.contains("recolour to pink") || lowered.contains("recolor to pink"),
            "Brand Kit documentation must forbid recolour to pink"
        );
        assert!(
            lowered.contains("teal"),
            "Brand Kit documentation must forbid teal"
        );
        assert!(
            lowered.contains("neon glow"),
            "Brand Kit documentation must forbid neon glow"
        );
        assert!(
            lowered.contains("silent deletion"),
            "Brand Kit documentation must forbid slogans that imply silent deletion"
        );
        assert!(
            docs.contains("#141210") && docs.contains("#F7F0E4"),
            "Brand Kit documentation must name warm ink and warm paper"
        );
    }

    #[test]
    fn forbidden_hues_are_absent_from_the_brand_kit() {
        let mut files = Vec::new();
        collect_files(&brand_dir(), &mut files);
        assert!(
            !files.is_empty(),
            "Brand Kit must contain identity files to inspect"
        );
        for path in files {
            let bytes = fs::read(&path).unwrap();
            if let Ok(body) = String::from_utf8(bytes.clone()) {
                assert_no_forbidden_hues(&path.display().to_string(), &body);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("png") {
                let icon = eframe::icon_data::from_png_bytes(&bytes).unwrap_or_else(|error| {
                    panic!("{} must decode as PNG: {error}", path.display());
                });
                assert!(
                    !opaque_pixels_near(&icon.rgba, [255, 0, 153], 20),
                    "{} must not contain magenta",
                    path.display()
                );
                assert!(
                    !opaque_pixels_near(&icon.rgba, [0, 255, 133], 20),
                    "{} must not contain neon mint",
                    path.display()
                );
                assert!(
                    !opaque_pixels_near(&icon.rgba, [121, 210, 195], 20),
                    "{} must not contain teal",
                    path.display()
                );
            }
        }
    }

    #[test]
    fn brand_kit_assets_contain_no_secrets_or_file_contents() {
        let mut files = Vec::new();
        collect_files(&brand_dir(), &mut files);
        files.push(repo_root().join("README.md"));
        for path in files {
            let bytes = fs::read(&path).unwrap();
            let body = String::from_utf8_lossy(&bytes);
            assert_no_secrets(&path.display().to_string(), &body);
        }
    }

    #[test]
    fn readme_uses_the_wordmark_or_lockup_rather_than_neon_screenshots() {
        let readme = read_text(&repo_root().join("README.md"));
        let lowered = readme.to_ascii_lowercase();
        assert!(
            readme.contains("docs/brand/lockup/") || readme.contains("docs/brand/wordmark/"),
            "README must reference a Brand Kit lockup or wordmark image"
        );
        for needle in ["neon", "seafoam", "screenshot"] {
            assert!(
                !lowered.contains(needle),
                "README must not use {needle} imagery that contradicts the identity"
            );
        }
    }

    #[test]
    fn github_avatar_and_facebook_profile_show_copper_and_steel_on_ink() {
        for relative in ["github/avatar.png", "facebook/profile.png"] {
            let bytes = fs::read(brand_dir().join(relative)).unwrap();
            let icon = eframe::icon_data::from_png_bytes(&bytes).unwrap();
            assert!(
                opaque_pixels_near(&icon.rgba, [20, 18, 16], 12),
                "{relative} must include the warm-ink plate"
            );
            assert!(
                opaque_pixels_near(&icon.rgba, [224, 138, 60], 28),
                "{relative} must include copper outbound pixels"
            );
            assert!(
                opaque_pixels_near(&icon.rgba, [138, 160, 184], 28),
                "{relative} must include steel inbound pixels"
            );
        }
    }
}
