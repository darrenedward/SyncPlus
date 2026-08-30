use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemizedRecord {
    code: String,
    path: PathBuf,
}

impl ItemizedRecord {
    pub fn new(code: impl Into<String>, path: PathBuf) -> Self {
        Self {
            code: code.into(),
            path,
        }
    }

    pub fn code(&self) -> &str {
        &self.code
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgressRecord {
    completed_bytes: u64,
    percent: u8,
}

impl ProgressRecord {
    pub const fn completed_bytes(&self) -> u64 {
        self.completed_bytes
    }

    pub const fn percent(&self) -> u8 {
        self.percent
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseDiagnostic {
    InvalidUtf8,
    InvalidItemizedRecord,
    InvalidEscape,
    InvalidProgressRecord,
    UnrecognizedRecord,
    TruncatedRecord,
    RecordTooLong,
    OutputTooLarge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedOutput {
    Itemized(ItemizedRecord),
    Progress(ProgressRecord),
    Diagnostic(ParseDiagnostic),
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ParsedTransferOutput {
    itemized: Vec<ItemizedRecord>,
    progress: Vec<ProgressRecord>,
    diagnostics: Vec<ParseDiagnostic>,
}

impl ParsedTransferOutput {
    pub fn itemized(&self) -> &[ItemizedRecord] {
        &self.itemized
    }

    pub fn progress(&self) -> &[ProgressRecord] {
        &self.progress
    }

    pub fn diagnostics(&self) -> &[ParseDiagnostic] {
        &self.diagnostics
    }

    pub const fn is_well_formed(&self) -> bool {
        self.diagnostics.is_empty()
    }

    pub(crate) fn push(&mut self, event: ParsedOutput) {
        match event {
            ParsedOutput::Itemized(record) => self.itemized.push(record),
            ParsedOutput::Progress(record) => self.progress.push(record),
            ParsedOutput::Diagnostic(diagnostic) => self.diagnostics.push(diagnostic),
        }
    }

}

/// Incrementally parses rsync's line-oriented itemized and progress output.
///
/// The parser never turns malformed input into an action. It retains only
/// typed records and diagnostic kinds, not raw process output or file content.
#[derive(Debug, Clone)]
pub struct TransferOutputParser {
    buffer: Vec<u8>,
    discarding_oversized_record: bool,
    max_record_bytes: usize,
    max_output_records: usize,
    max_output_bytes: usize,
    output_record_count: usize,
    output_byte_count: usize,
    output_limit_reached: bool,
}

impl Default for TransferOutputParser {
    fn default() -> Self {
        Self::new()
    }
}

impl TransferOutputParser {
    pub const DEFAULT_MAX_RECORD_BYTES: usize = 1024 * 1024;
    pub const DEFAULT_MAX_OUTPUT_RECORDS: usize = 1_000_000;
    pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;

    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            discarding_oversized_record: false,
            max_record_bytes: Self::DEFAULT_MAX_RECORD_BYTES,
            max_output_records: Self::DEFAULT_MAX_OUTPUT_RECORDS,
            max_output_bytes: Self::DEFAULT_MAX_OUTPUT_BYTES,
            output_record_count: 0,
            output_byte_count: 0,
            output_limit_reached: false,
        }
    }

    pub fn with_max_record_bytes(max_record_bytes: usize) -> Self {
        Self::with_limits(max_record_bytes, Self::DEFAULT_MAX_OUTPUT_RECORDS)
    }

    pub fn with_limits(max_record_bytes: usize, max_output_records: usize) -> Self {
        Self::with_output_limits(
            max_record_bytes,
            max_output_records,
            Self::DEFAULT_MAX_OUTPUT_BYTES,
        )
    }

    pub fn with_output_limits(
        max_record_bytes: usize,
        max_output_records: usize,
        max_output_bytes: usize,
    ) -> Self {
        Self {
            max_record_bytes: max_record_bytes.max(1),
            max_output_records: max_output_records.max(1),
            max_output_bytes: max_output_bytes.max(1),
            ..Self::new()
        }
    }

    pub fn feed(&mut self, chunk: &[u8]) -> Vec<ParsedOutput> {
        let mut output = Vec::new();
        for byte in chunk {
            if self.discarding_oversized_record {
                if *byte == b'\n' {
                    self.discarding_oversized_record = false;
                    output.push(ParsedOutput::Diagnostic(ParseDiagnostic::RecordTooLong));
                }
                continue;
            }

            if *byte == b'\n' {
                let line = std::mem::take(&mut self.buffer);
                self.append_line(&mut output, &line);
                continue;
            }

            self.buffer.push(*byte);
            if self.buffer.len() > self.max_record_bytes {
                self.buffer.clear();
                self.discarding_oversized_record = true;
            }
        }
        output
    }

    pub fn finish(&mut self) -> Vec<ParsedOutput> {
        if self.buffer.is_empty() && !self.discarding_oversized_record {
            return Vec::new();
        }
        let diagnostic = if self.discarding_oversized_record {
            ParseDiagnostic::RecordTooLong
        } else {
            ParseDiagnostic::TruncatedRecord
        };
        self.buffer.clear();
        self.discarding_oversized_record = false;
        vec![ParsedOutput::Diagnostic(diagnostic)]
    }

    fn append_line(&mut self, output: &mut Vec<ParsedOutput>, line: &[u8]) {
        if self.output_limit_reached {
            return;
        }
        if self.output_byte_count.saturating_add(line.len()) > self.max_output_bytes {
            output.push(ParsedOutput::Diagnostic(ParseDiagnostic::OutputTooLarge));
            self.output_limit_reached = true;
            return;
        }
        for event in parse_line(line) {
            if self.output_record_count >= self.max_output_records {
                output.push(ParsedOutput::Diagnostic(ParseDiagnostic::OutputTooLarge));
                self.output_limit_reached = true;
                return;
            }
            self.output_record_count += 1;
            output.push(event);
        }
        self.output_byte_count = self.output_byte_count.saturating_add(line.len());
    }

    pub fn parse_chunks<I, B>(chunks: I) -> ParsedTransferOutput
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let mut parser = Self::new();
        let mut output = ParsedTransferOutput::default();
        for chunk in chunks {
            for event in parser.feed(chunk.as_ref()) {
                output.push(event);
            }
        }
        for event in parser.finish() {
            output.push(event);
        }
        output
    }
}

fn parse_line(line: &[u8]) -> Vec<ParsedOutput> {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line.is_empty() {
        return Vec::new();
    }

    if is_known_rsync_info(line) {
        return Vec::new();
    }

    if looks_like_itemized_record(line) {
        return match split_itemized_line(line) {
            Some((code, encoded_path)) => match unescape_path(encoded_path) {
                Ok(path) if !path.as_os_str().is_empty() => {
                    vec![ParsedOutput::Itemized(ItemizedRecord::new(code, path))]
                }
                Ok(_) => vec![ParsedOutput::Diagnostic(ParseDiagnostic::InvalidItemizedRecord)],
                Err(diagnostic) => vec![ParsedOutput::Diagnostic(diagnostic)],
            },
            None => vec![ParsedOutput::Diagnostic(ParseDiagnostic::InvalidItemizedRecord)],
        };
    }

    if line.contains(&b'%') {
        return match parse_progress(line) {
            Some(progress) => vec![ParsedOutput::Progress(progress)],
            None => vec![ParsedOutput::Diagnostic(ParseDiagnostic::InvalidProgressRecord)],
        };
    }

    vec![ParsedOutput::Diagnostic(ParseDiagnostic::UnrecognizedRecord)]
}

fn looks_like_itemized_record(line: &[u8]) -> bool {
    matches!(line.first(), Some(b'>' | b'<' | b'c' | b'h' | b'.' | b'*'))
        || line.starts_with(b"*deleting")
}

fn split_itemized_line(line: &[u8]) -> Option<(&str, &[u8])> {
    let separator = line.iter().position(u8::is_ascii_whitespace)?;
    let code = std::str::from_utf8(&line[..separator]).ok()?;
    let code_bytes = code.as_bytes();
    if code_bytes.len() != 11
        || !matches!(code_bytes[0], b'>' | b'<' | b'c' | b'h' | b'.' | b'*')
        || !matches!(code_bytes[1], b'f' | b'd' | b'L' | b'D' | b'S')
        || !code_bytes[2..].iter().all(|byte| {
            matches!(
                byte,
                b'.' | b'+' | b'c' | b's' | b't' | b'p' | b'o' | b'g' | b'u' | b'n' | b'a'
                    | b'x' | b'?'
            )
        })
    {
        return None;
    }
    let path = line[separator..]
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .map(|offset| &line[separator + offset..])?;
    Some((code, path))
}

fn is_known_rsync_info(line: &[u8]) -> bool {
    line == b"sending incremental file list"
        || line == b"receiving incremental file list"
        || line.starts_with(b"building file list")
        || line.starts_with(b"created directory ")
        || line.starts_with(b"sent ")
        || line.starts_with(b"total size is ")
        || line.starts_with(b"delta-transmission enabled")
        || line.starts_with(b"Number of files: ")
        || line.starts_with(b"Number of created files: ")
        || line.starts_with(b"Number of deleted files: ")
        || line.starts_with(b"Number of regular files transferred: ")
        || line.starts_with(b"Total file size: ")
        || line.starts_with(b"Total transferred file size: ")
        || line.starts_with(b"Literal data: ")
        || line.starts_with(b"Matched data: ")
        || line.starts_with(b"File list size: ")
        || line.starts_with(b"File list generation time: ")
        || line.starts_with(b"File list transfer time: ")
        || line.starts_with(b"Total bytes sent: ")
        || line.starts_with(b"Total bytes received: ")
        || line.starts_with(b"sent_bytes=")
        || line.starts_with(b"received_bytes=")
}

fn parse_progress(line: &[u8]) -> Option<ProgressRecord> {
    let text = std::str::from_utf8(line).ok()?;
    let mut fields = text.split_ascii_whitespace();
    let completed_bytes = fields.next()?.replace(',', "").parse().ok()?;
    let percent_text = fields.next()?.strip_suffix('%')?;
    let percent = percent_text.parse::<u8>().ok()?;
    if percent > 100 {
        return None;
    }
    Some(ProgressRecord {
        completed_bytes,
        percent,
    })
}

fn unescape_path(encoded: &[u8]) -> Result<PathBuf, ParseDiagnostic> {
    let mut decoded = Vec::with_capacity(encoded.len());
    let mut index = 0;
    while index < encoded.len() {
        if encoded[index] != b'\\' {
            decoded.push(encoded[index]);
            index += 1;
            continue;
        }

        index += 1;
        let Some(&escaped) = encoded.get(index) else {
            return Err(ParseDiagnostic::InvalidEscape);
        };
        match escaped {
            b'\\' => {
                decoded.push(b'\\');
                index += 1;
            }
            b'n' => {
                decoded.push(b'\n');
                index += 1;
            }
            b'r' => {
                decoded.push(b'\r');
                index += 1;
            }
            b't' => {
                decoded.push(b'\t');
                index += 1;
            }
            b'x' => {
                let first = *encoded.get(index + 1).ok_or(ParseDiagnostic::InvalidEscape)?;
                let second = *encoded.get(index + 2).ok_or(ParseDiagnostic::InvalidEscape)?;
                let high = hex_digit(first).ok_or(ParseDiagnostic::InvalidEscape)?;
                let low = hex_digit(second).ok_or(ParseDiagnostic::InvalidEscape)?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            other if other.is_ascii_digit() => {
                let mut value = 0u8;
                let mut digits = 0;
                while digits < 3 {
                    let Some(&digit) = encoded.get(index + digits) else {
                        break;
                    };
                    if !(b'0'..=b'7').contains(&digit) {
                        break;
                    }
                    value = value
                        .checked_mul(8)
                        .and_then(|value| value.checked_add(digit - b'0'))
                        .ok_or(ParseDiagnostic::InvalidEscape)?;
                    digits += 1;
                }
                if digits == 0 {
                    return Err(ParseDiagnostic::InvalidEscape);
                }
                decoded.push(value);
                index += digits;
            }
            _ => return Err(ParseDiagnostic::InvalidEscape),
        }
    }

    if decoded.contains(&0) {
        return Err(ParseDiagnostic::InvalidEscape);
    }
    if std::str::from_utf8(&decoded).is_err() {
        return Err(ParseDiagnostic::InvalidUtf8);
    }
    Ok(PathBuf::from(String::from_utf8(decoded).expect("UTF-8 was checked")))
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{ParseDiagnostic, ParsedOutput, TransferOutputParser};

    const ITEMIZED: &[u8] = b">f+++++++++ folder/file with spaces \\xE2\\x98\\x83.txt\n";

    #[test]
    fn parses_identically_when_input_is_split_at_every_byte() {
        let whole = TransferOutputParser::parse_chunks([ITEMIZED, b" 1024 50%  1.00kB/s\n"]);
        let mut parser = TransferOutputParser::new();
        let mut split = Vec::new();
        for byte in ITEMIZED
            .iter()
            .copied()
            .chain(b" 1024 50%  1.00kB/s\n".iter().copied())
        {
            split.extend(parser.feed(&[byte]));
        }
        split.extend(parser.finish());
        let mut split_output = super::ParsedTransferOutput::default();
        for event in split {
            split_output.push(event);
        }
        assert_eq!(whole, split_output);
        assert_eq!(whole.itemized()[0].path().to_string_lossy(), "folder/file with spaces ☃.txt");
        assert_eq!(whole.progress()[0].completed_bytes(), 1024);
    }

    #[test]
    fn malformed_escape_and_truncated_records_are_diagnostics() {
        let output = TransferOutputParser::parse_chunks([
            b">f+++++++++ bad\\q.txt\n".as_slice(),
            b">f+++++++++ truncated".as_slice(),
        ]);
        assert_eq!(
            output.diagnostics(),
            &[ParseDiagnostic::InvalidEscape, ParseDiagnostic::TruncatedRecord]
        );
        assert!(output.itemized().is_empty());
    }

    #[test]
    fn malformed_progress_and_oversized_records_cannot_become_progress() {
        let parser = TransferOutputParser::with_max_record_bytes(8);
        let mut output = super::ParsedTransferOutput::default();
        for event in parser_with(parser, b"123 101%\n") {
            output.push(event);
        }
        assert!(output.progress().is_empty());
        assert!(output
            .diagnostics()
            .contains(&ParseDiagnostic::InvalidProgressRecord));

        let mut oversized_parser = TransferOutputParser::with_max_record_bytes(8);
        let mut oversized = super::ParsedTransferOutput::default();
        for event in oversized_parser.feed(b"123456789\n123 50%\n") {
            oversized.push(event);
        }
        for event in oversized_parser.finish() {
            oversized.push(event);
        }
        assert_eq!(oversized.progress().len(), 1);
        assert_eq!(oversized.progress()[0].completed_bytes(), 123);
        assert!(oversized
            .diagnostics()
            .contains(&ParseDiagnostic::RecordTooLong));
    }

    #[test]
    fn malformed_itemized_and_unknown_records_are_diagnostics() {
        let output = TransferOutputParser::parse_chunks([
            b"*deleting removed.txt\n".as_slice(),
            b">x+++++++++ malformed.txt\n".as_slice(),
            b"unexpected output\n".as_slice(),
            b"created directory destination\n".as_slice(),
            b"sending incremental file list\n".as_slice(),
        ]);
        assert_eq!(output.itemized().len(), 0);
        assert_eq!(
            output.diagnostics(),
            &[
                ParseDiagnostic::InvalidItemizedRecord,
                ParseDiagnostic::InvalidItemizedRecord,
                ParseDiagnostic::UnrecognizedRecord,
            ]
        );
    }

    #[test]
    fn output_record_limit_becomes_a_diagnostic() {
        let mut parser = TransferOutputParser::with_limits(1024, 1);
        let mut output = super::ParsedTransferOutput::default();
        for event in parser.feed(b"123 10%\n456 20%\n") {
            output.push(event);
        }
        for event in parser.finish() {
            output.push(event);
        }
        assert_eq!(output.progress().len(), 1);
        assert!(output
            .diagnostics()
            .contains(&ParseDiagnostic::OutputTooLarge));
    }

    #[test]
    fn output_byte_limit_stops_unbounded_process_output() {
        let mut parser = TransferOutputParser::with_output_limits(1024, 100, 5);
        let mut output = super::ParsedTransferOutput::default();
        for event in parser.feed(b"123 10%\n") {
            output.push(event);
        }
        assert!(output.progress().is_empty());
        assert_eq!(
            output.diagnostics(),
            &[ParseDiagnostic::OutputTooLarge]
        );
    }

    #[test]
    fn parser_events_are_typed_and_do_not_include_raw_output() {
        let output = TransferOutputParser::parse_chunks([b">f+++++++++ report.txt\n".as_slice()]);
        assert!(matches!(
            ParsedOutput::Itemized(output.itemized()[0].clone()),
            ParsedOutput::Itemized(_)
        ));
    }

    fn parser_with(mut parser: TransferOutputParser, input: &[u8]) -> Vec<ParsedOutput> {
        let mut output = parser.feed(input);
        output.extend(parser.finish());
        output
    }
}
