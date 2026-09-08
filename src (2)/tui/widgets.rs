use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

/// Represents the status of a sector block on the disk map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockStatus {
    Unscanned,
    Scanning,
    ScannedClean,
    FoundFiles,
    Error,
}

/// Generates a visual hex dump from a byte buffer.
pub fn generate_hex_dump(data: &[u8]) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    // Column Header
    lines.push(Line::from(vec![
        Span::styled("Offset    ", Style::default().fg(Color::Blue)),
        Span::styled(
            "00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  ",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "ASCII",
            Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD),
        ),
    ]));

    if data.is_empty() {
        lines.push(Line::from(vec![Span::raw("No data loaded. Select a file to inspect.")]));
        return lines;
    }

    for (i, chunk) in data.chunks(16).enumerate() {
        let offset = i * 16;
        let mut spans = vec![Span::styled(
            format!("{:08X}  ", offset),
            Style::default().fg(Color::Blue),
        )];

        // Hex section
        for (j, &byte) in chunk.iter().enumerate() {
            let byte_str = format!("{:02X} ", byte);
            let style = match byte {
                0x00 => Style::default().fg(Color::Gray),
                0x20..=0x7E => Style::default().fg(Color::Green),
                _ => Style::default().fg(Color::White),
            };
            spans.push(Span::styled(byte_str, style));

            if j == 7 {
                spans.push(Span::raw(" "));
            }
        }

        // Padding for incomplete lines
        if chunk.len() < 16 {
            let padding_len = 16 - chunk.len();
            let mut padding = "   ".repeat(padding_len);
            if chunk.len() <= 7 {
                padding.push(' ');
            }
            spans.push(Span::raw(padding));
        }

        spans.push(Span::styled(" |", Style::default().fg(Color::Cyan)));

        // ASCII section
        for &byte in chunk {
            let char_str = if (0x20..=0x7E).contains(&byte) {
                (byte as char).to_string()
            } else {
                ".".to_string()
            };
            let style = match byte {
                0x00 => Style::default().fg(Color::Gray),
                0x20..=0x7E => Style::default().fg(Color::Green),
                _ => Style::default().fg(Color::Yellow),
            };
            spans.push(Span::styled(char_str, style));
        }

        spans.push(Span::styled("|", Style::default().fg(Color::Cyan)));
        lines.push(Line::from(spans));
    }

    lines
}

/// Generates a live, dynamic sector map paragraph based on terminal size.
pub fn generate_dynamic_sector_map(
    total_sectors: u64,
    current_sector: u64,
    file_offsets: &[u64],
    error_offsets: &[u64],
    sector_size: u64,
    width: usize,
    height: usize,
) -> Paragraph<'static> {
    let num_blocks = width * height;
    if num_blocks == 0 || total_sectors == 0 {
        return Paragraph::new("No active scanning session");
    }

    let sectors_per_block = total_sectors.div_ceil(num_blocks as u64);
    let mut lines = Vec::new();

    for y in 0..height {
        let mut spans = Vec::new();
        for x in 0..width {
            let block_idx = (y * width + x) as u64;
            if block_idx >= num_blocks as u64 {
                break;
            }

            let block_start_sector = block_idx * sectors_per_block;
            let block_end_sector = (block_idx + 1) * sectors_per_block;

            let status = if current_sector < block_start_sector {
                BlockStatus::Unscanned
            } else if current_sector >= block_start_sector && current_sector < block_end_sector {
                BlockStatus::Scanning
            } else {
                let has_error = error_offsets.iter().any(|&offset| {
                    let s = offset / sector_size;
                    s >= block_start_sector && s < block_end_sector
                });

                let has_files = file_offsets.iter().any(|&offset| {
                    let s = offset / sector_size;
                    s >= block_start_sector && s < block_end_sector
                });

                if has_error {
                    BlockStatus::Error
                } else if has_files {
                    BlockStatus::FoundFiles
                } else {
                    BlockStatus::ScannedClean
                }
            };

            let (char_str, color) = match status {
                BlockStatus::Unscanned => ("░", Color::Gray),
                BlockStatus::Scanning => ("▓", Color::Yellow),
                BlockStatus::ScannedClean => ("█", Color::Gray),
                BlockStatus::FoundFiles => ("█", Color::Green),
                BlockStatus::Error => ("█", Color::Red),
            };

            spans.push(Span::styled(char_str, Style::default().fg(color)));
        }
        if !spans.is_empty() {
            lines.push(Line::from(spans));
        }
    }

    Paragraph::new(lines)
}
