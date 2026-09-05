pub const COMMON_PATTERNS: [(&str, &str); 6] = [
    ("*.tmp", "Temporary files"),
    ("*.exe", "Windows executables"),
    ("*.bak", "Backup copies"),
    ("node_modules/", "Node modules"),
    (".git/", "Git metadata"),
    (".cache/", "Cache folders"),
];

pub fn append_pattern(exclusions: &mut String, pattern: &str) {
    let already = exclusions.lines().any(|line| line.trim() == pattern);
    if already {
        return;
    }
    if !exclusions.is_empty() && !exclusions.ends_with('\n') {
        exclusions.push('\n');
    }
    exclusions.push_str(pattern);
    exclusions.push('\n');
}

#[cfg(test)]
mod tests {
    use super::{COMMON_PATTERNS, append_pattern};

    #[test]
    fn one_list_holds_file_and_folder_patterns() {
        assert!(
            COMMON_PATTERNS
                .iter()
                .any(|(pattern, _)| *pattern == "*.tmp")
        );
        assert!(
            COMMON_PATTERNS
                .iter()
                .any(|(pattern, _)| *pattern == "node_modules/")
        );
        assert!(
            !COMMON_PATTERNS
                .iter()
                .any(|(pattern, _)| pattern.starts_with("/home"))
        );
        let mut exclusions = String::new();
        append_pattern(&mut exclusions, "*.tmp");
        append_pattern(&mut exclusions, "*.tmp");
        append_pattern(&mut exclusions, "node_modules/");
        assert_eq!(exclusions, "*.tmp\nnode_modules/\n");
    }
}
