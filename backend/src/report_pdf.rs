use crate::{
    domain::{Report, scanner_names},
    report_branding::{Branding, Pixels, decode_logo},
    store::{Scan, now},
};
use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use flate2::{Compression, write::ZlibEncoder};
use pdf_writer::{Content, Filter, Finish, Name, Pdf, Rect, Ref, Str, TextStr};
use std::io::Write;

const PAGE_WIDTH: f32 = 612.0;
const PAGE_HEIGHT: f32 = 792.0;
const LEFT: f32 = 40.0;
const WIDTH: f32 = PAGE_WIDTH - 2.0 * LEFT;
const RIGHT: f32 = LEFT + WIDTH;
const TABLE_BOTTOM: f32 = 93.0;
const BODY_SIZE: f32 = 8.5;
const LINE_HEIGHT: f32 = 11.0;
const CELL_PADDING: f32 = 6.0;
const REGULAR: Name = Name(b"Regular");
const BOLD: Name = Name(b"Bold");
const LOGO: Name = Name(b"Logo");
const LOGO_REF: Ref = Ref::new(5);
const MASK_REF: Ref = Ref::new(6);

type Color = u32;
const INK: Color = 0x182235;
const MUTED: Color = 0x586579;
const CANVAS: Color = 0xf5f7fb;
const INSET: Color = 0xf0f3f8;
const LINE: Color = 0xdce3ec;
const ACCENT: Color = 0x345eaa;
const SEVERITIES: [(&str, Color, Color); 5] = [
    ("Critical", 0xa0233f, 0xfbe9ec),
    ("High", 0x8a421c, 0xfcebdc),
    ("Medium", 0x6d540b, 0xf8efcc),
    ("Low", 0x27586b, 0xe5f1f3),
    ("Unknown", MUTED, INSET),
];

pub fn build(scan: &Scan, report: &Report, branding: &Branding, scanner: &str) -> Result<Vec<u8>> {
    let mut pdf = Pdf::new();
    let tree = Ref::new(1);
    let catalog = Ref::new(2);
    let regular_ref = Ref::new(3);
    let bold_ref = Ref::new(4);
    pdf.catalog(catalog).pages(tree);
    pdf.type1_font(regular_ref)
        .base_font(Name(b"Helvetica"))
        .encoding_predefined(Name(b"WinAnsiEncoding"));
    pdf.type1_font(bold_ref)
        .base_font(Name(b"Helvetica-Bold"))
        .encoding_predefined(Name(b"WinAnsiEncoding"));
    pdf.document_info(Ref::new(7))
        .title(TextStr("Container image vulnerability report"))
        .author(TextStr(branding.organization()))
        .creator(TextStr(crate::PRODUCT_NAME));
    let logo = embed_logo(&mut pdf, branding)?;

    let mut layout = Layout {
        pages: vec![Content::new()],
        y: 686.0,
    };
    layout.summary(scan, report, scanner);

    let mut findings: Vec<_> = report.findings.iter().collect();
    findings.sort_by(|a, b| {
        severity(&a.severity)
            .cmp(&severity(&b.severity))
            .then_with(|| a.id.cmp(&b.id))
    });
    let findings: Vec<_> = findings
        .into_iter()
        .map(|v| {
            let identifiers = std::iter::once(v.id.as_str())
                .chain(v.aliases.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join("\n");
            (v, identifiers, scanner_names(&v.detected_by))
        })
        .collect();
    layout.table(
        "Vulnerability findings",
        [
            "Advisory ID",
            "Severity",
            "Package",
            "Installed",
            "Fixed in",
            "Detected by",
            "Title",
        ],
        [121.0, 46.0, 69.0, 48.0, 52.0, 69.0, 127.0],
        6.0,
        findings.iter().map(|(v, ids, engines)| {
            let level = severity(&v.severity);
            (
                [
                    ids.as_str(),
                    SEVERITIES[level].0,
                    &v.package,
                    &v.installed,
                    &v.fixed,
                    engines.as_str(),
                    &v.title,
                ],
                Some((1, SEVERITIES[level].1)),
            )
        }),
    );
    if !report.checks.is_empty() {
        layout.table(
            "Configuration, secrets and licenses",
            ["Type", "ID", "Severity", "Target", "Title"],
            [76.0, 88.0, 58.0, 112.0, 198.0],
            6.0,
            report.checks.iter().map(|v| {
                (
                    [v.category.as_str(), &v.id, &v.severity, &v.target, &v.title],
                    Some((2, SEVERITIES[severity(&v.severity)].1)),
                )
            }),
        );
    }
    if !report.packages.is_empty() {
        layout.table(
            "Package inventory",
            ["Package", "Ecosystem", "Version"],
            [240.0, 100.0, 192.0],
            2.5,
            report
                .packages
                .iter()
                .map(|p| ([p.name.as_str(), &p.ecosystem, &p.version], None)),
        );
    }

    let count = layout.pages.len();
    let mut references = Vec::with_capacity(count);
    for (index, mut content) in layout.pages.into_iter().enumerate() {
        let page_ref = Ref::new(8 + 2 * index as i32);
        let stream_ref = Ref::new(9 + 2 * index as i32);
        references.push(page_ref);
        let mut page = pdf.page(page_ref);
        page.parent(tree)
            .media_box(Rect::new(0.0, 0.0, PAGE_WIDTH, PAGE_HEIGHT))
            .contents(stream_ref);
        let mut resources = page.resources();
        resources
            .fonts()
            .pair(REGULAR, regular_ref)
            .pair(BOLD, bold_ref);
        if logo.is_some() {
            resources.x_objects().pair(LOGO, LOGO_REF);
        }
        resources.finish();
        page.finish();
        frame(&mut content, branding, logo, index + 1, count);
        pdf.stream(stream_ref, &content.finish());
    }
    pdf.pages(tree).kids(references).count(count as i32);
    Ok(pdf.finish())
}

fn severity(value: &str) -> usize {
    SEVERITIES
        .iter()
        .position(|(label, _, _)| label.eq_ignore_ascii_case(value))
        .unwrap_or(4)
}

struct Layout {
    pages: Vec<Content>,
    y: f32,
}

impl Layout {
    fn content(&mut self) -> &mut Content {
        self.pages
            .last_mut()
            .expect("the report starts with one page")
    }

    fn new_page(&mut self) {
        self.pages.push(Content::new());
        self.y = 686.0;
    }

    fn summary(&mut self, scan: &Scan, report: &Report, scanner: &str) {
        let content = self.content();
        text(
            content,
            LEFT,
            686.0,
            24.0,
            BOLD,
            INK,
            "Container image vulnerability report",
        );
        let mut y = 657.0;
        text(content, LEFT, y, 9.0, BOLD, MUTED, "Image reference");
        y -= 19.0;
        for line in wrap(&scan.reference, WIDTH, 13.0, BOLD) {
            write_text(content, LEFT, y, 13.0, BOLD, INK, &line);
            y -= 16.0;
        }
        y -= 10.0;
        let date = date_label(scan.finished_at.as_deref().unwrap_or(&scan.created_at));
        let generated = date_label(&now());
        let details = [
            ("Platform", scan.platform.as_str()),
            ("Scanner", scanner),
            ("Scan date", &date),
            ("Generated at", &generated),
        ];
        for pair in details.chunks_exact(2) {
            let mut lines_used = 1;
            for (index, (label, value)) in pair.iter().enumerate() {
                let x = LEFT + index as f32 * (WIDTH / 2.0);
                text(content, x, y, 9.0, BOLD, MUTED, label);
                let lines = wrap(value, WIDTH / 2.0 - 14.0, 10.0, REGULAR);
                lines_used = lines_used.max(lines.len());
                for (index, line) in lines.iter().enumerate() {
                    write_text(
                        content,
                        x,
                        y - 14.0 - index as f32 * 12.0,
                        10.0,
                        REGULAR,
                        INK,
                        line,
                    );
                }
            }
            y -= 22.0 + lines_used as f32 * 12.0;
        }
        text(content, LEFT, y, 9.0, BOLD, MUTED, "Digest");
        let digest = report
            .digest
            .as_deref()
            .or_else(|| scan.reference.split_once('@').map(|(_, digest)| digest));
        for line in wrap(digest.unwrap_or("Unavailable"), WIDTH, 10.0, REGULAR) {
            y -= 14.0;
            write_text(content, LEFT, y, 10.0, REGULAR, INK, &line);
        }

        y -= 20.0;
        let counts = &report.counts;
        let counts = [
            counts.critical,
            counts.high,
            counts.medium,
            counts.low,
            counts.unknown,
        ];
        let levels = if counts[4] > 0 { 5 } else { 4 };
        let box_width = (WIDTH - 8.0 * (levels - 1) as f32) / levels as f32;
        for (index, ((label, foreground, background), count)) in
            SEVERITIES.iter().zip(counts).take(levels).enumerate()
        {
            let x = LEFT + index as f32 * (box_width + 8.0);
            rectangle(content, x, y - 50.0, box_width, 50.0, *background);
            text(content, x + 10.0, y - 16.0, 9.0, BOLD, *foreground, label);
            text(
                content,
                x + 10.0,
                y - 37.0,
                20.0,
                BOLD,
                *foreground,
                &count.to_string(),
            );
        }
        self.y = y - 76.0;
    }

    fn table<'a, const N: usize>(
        &mut self,
        title: &str,
        headers: [&str; N],
        widths: [f32; N],
        row_padding: f32,
        rows: impl IntoIterator<Item = ([&'a str; N], Option<(usize, Color)>)>,
    ) {
        if self.y < TABLE_BOTTOM + 75.0 {
            self.new_page();
        }
        self.table_header(title, &headers, &widths);
        let mut empty = true;
        for (index, (cells, accent)) in rows.into_iter().enumerate() {
            empty = false;
            let cells: [_; N] = std::array::from_fn(|column| {
                let bold = accent.is_some_and(|(key, _)| key == column);
                let font = if bold { BOLD } else { REGULAR };
                let value = cells[column];
                wrap(
                    if value.is_empty() { "—" } else { value },
                    widths[column] - 2.0 * CELL_PADDING,
                    BODY_SIZE,
                    font,
                )
            });
            let line_count = cells.iter().map(Vec::len).max().unwrap_or(1);
            let mut start = 0;
            while start < line_count {
                let mut capacity =
                    ((self.y - TABLE_BOTTOM - 2.0 * row_padding) / LINE_HEIGHT).floor() as usize;
                let fresh_page_capacity = ((686.0 - 31.0 - TABLE_BOTTOM - 2.0 * row_padding)
                    / LINE_HEIGHT)
                    .floor() as usize;
                if capacity == 0
                    || (start == 0 && line_count > capacity && line_count <= fresh_page_capacity)
                {
                    self.new_page();
                    self.table_header(&format!("{title} (continued)"), &headers, &widths);
                    capacity = ((self.y - TABLE_BOTTOM - 2.0 * row_padding) / LINE_HEIGHT).floor()
                        as usize;
                }
                let end = (start + capacity).min(line_count);
                let y = self.y;
                let height = (end - start) as f32 * LINE_HEIGHT + 2.0 * row_padding;
                let content = self.content();
                if index % 2 == 1 {
                    rectangle(content, LEFT, y - height, WIDTH, height, CANVAS);
                }
                let mut x = LEFT;
                for (column, (lines, width)) in cells.iter().zip(widths).enumerate() {
                    let (font, color) = match accent {
                        Some((key, color)) if key == column => (BOLD, color),
                        _ => (REGULAR, INK),
                    };
                    for (line_index, line) in lines.iter().take(end).skip(start).enumerate() {
                        write_text(
                            content,
                            x + CELL_PADDING,
                            y - row_padding - BODY_SIZE - line_index as f32 * LINE_HEIGHT,
                            BODY_SIZE,
                            font,
                            color,
                            line,
                        );
                    }
                    x += width;
                }
                rule(content, y - height);
                self.y -= height;
                start = end;
            }
        }
        if empty {
            let y = self.y - 17.0;
            text(
                self.content(),
                LEFT + CELL_PADDING,
                y,
                9.0,
                REGULAR,
                MUTED,
                "No vulnerabilities found.",
            );
            self.y -= 24.0;
        }
        self.y -= 28.0;
    }

    fn table_header(&mut self, title: &str, headers: &[&str], widths: &[f32]) {
        let y = self.y;
        let content = self.content();
        text(content, LEFT, y, 14.0, BOLD, INK, title);
        rectangle(content, LEFT, y - 31.0, WIDTH, 22.0, INSET);
        let mut x = LEFT;
        for (header, width) in headers.iter().zip(widths) {
            text(
                content,
                x + CELL_PADDING,
                y - 23.0,
                8.5,
                BOLD,
                MUTED,
                header,
            );
            x += width;
        }
        rule(content, y - 31.0);
        self.y -= 31.0;
    }
}

fn frame(
    content: &mut Content,
    branding: &Branding,
    logo: Option<(f32, f32)>,
    page: usize,
    count: usize,
) {
    rectangle(content, 0.0, PAGE_HEIGHT - 5.0, PAGE_WIDTH, 5.0, ACCENT);
    rule(content, 721.0);
    let mut x = LEFT;
    if let Some((width, height)) = logo {
        content
            .save_state()
            .transform([width, 0.0, 0.0, height, LEFT, 752.0 - height / 2.0])
            .x_object(LOGO)
            .restore_state();
        x += width + 12.0;
    }
    let organization = branding.organization();
    let mut size = 15.0;
    let mut lines = wrap(organization, RIGHT - x, size, BOLD);
    while lines.len() > 2 {
        size -= 0.5;
        lines = wrap(organization, RIGHT - x, size, BOLD);
    }
    let y = if lines.len() == 1 { 747.0 } else { 752.0 };
    for (index, line) in lines.iter().enumerate() {
        write_text(
            content,
            x,
            y - index as f32 * (size + 1.0),
            size,
            BOLD,
            INK,
            line,
        );
    }

    rule(content, 81.0);
    let label = format!("Page {page} of {count}");
    let label_bytes = win_ansi(&label);
    write_text(
        content,
        RIGHT - width(&label_bytes, 9.0, BOLD),
        65.0,
        9.0,
        BOLD,
        MUTED,
        &label_bytes,
    );
    let mut footer_size = 8.5;
    let (organization_lines, footer_lines) = loop {
        let organization_lines = wrap(organization, WIDTH - 90.0, footer_size, BOLD);
        let footer_lines = if branding.footer.is_empty() {
            Vec::new()
        } else {
            wrap(&branding.footer, WIDTH - 90.0, footer_size, REGULAR)
        };
        if organization_lines.len() + footer_lines.len() <= 6 {
            break (organization_lines, footer_lines);
        }
        footer_size -= 0.5;
    };
    let mut y = 65.0;
    for (lines, font, color) in [
        (organization_lines, BOLD, INK),
        (footer_lines, REGULAR, MUTED),
    ] {
        for line in lines {
            write_text(content, LEFT, y, footer_size, font, color, &line);
            y -= 11.0;
        }
    }
}

fn embed_logo(pdf: &mut Pdf, branding: &Branding) -> Result<Option<(f32, f32)>> {
    let Some(logo) = &branding.logo else {
        return Ok(None);
    };
    let original = STANDARD.decode(&logo.data)?;
    let image = decode_logo(&logo.content_type, &original)?;
    let (width, height) = (image.width as i32, image.height as i32);
    match image.pixels {
        Pixels::Png { rgb, alpha } => {
            let compressed = compress(&rgb)?;
            let mut object = pdf.image_xobject(LOGO_REF, &compressed);
            object.filter(Filter::FlateDecode);
            object.width(width).height(height).bits_per_component(8);
            object.color_space().device_rgb();
            if alpha.is_some() {
                object.s_mask(MASK_REF);
            }
            object.finish();
            if let Some(alpha) = alpha {
                let compressed = compress(&alpha)?;
                let mut mask = pdf.image_xobject(MASK_REF, &compressed);
                mask.filter(Filter::FlateDecode);
                mask.width(width).height(height).bits_per_component(8);
                mask.color_space().device_gray();
            }
        }
        Pixels::Jpeg(format) => {
            let mut object = pdf.image_xobject(LOGO_REF, &original);
            object.filter(Filter::DctDecode);
            object.width(width).height(height).bits_per_component(8);
            match format {
                jpeg_decoder::PixelFormat::L8 => {
                    object.color_space().device_gray();
                }
                jpeg_decoder::PixelFormat::CMYK32 => {
                    object.color_space().device_cmyk();
                    object.decode([1.0, 0.0, 1.0, 0.0, 1.0, 0.0, 1.0, 0.0]);
                }
                _ => {
                    object.color_space().device_rgb();
                }
            }
        }
    }
    let scale = (100.0 / width as f32).min(32.0 / height as f32);
    Ok(Some((width as f32 * scale, height as f32 * scale)))
}

fn compress(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes)?;
    Ok(encoder.finish()?)
}

fn date_label(value: &str) -> String {
    DateTime::parse_from_rfc3339(value)
        .map(|date| {
            date.with_timezone(&Utc)
                .format("%b %d, %Y %H:%M UTC")
                .to_string()
        })
        .unwrap_or_else(|_| value.to_owned())
}

fn channels(color: Color) -> (f32, f32, f32) {
    (
        (color >> 16) as f32 / 255.0,
        ((color >> 8) & 255) as f32 / 255.0,
        (color & 255) as f32 / 255.0,
    )
}

fn rectangle(content: &mut Content, x: f32, y: f32, width: f32, height: f32, color: Color) {
    let (r, g, b) = channels(color);
    content
        .set_fill_rgb(r, g, b)
        .rect(x, y, width, height)
        .fill_nonzero();
}

fn rule(content: &mut Content, y: f32) {
    let (r, g, b) = channels(LINE);
    content
        .set_stroke_rgb(r, g, b)
        .set_line_width(0.55)
        .move_to(LEFT, y)
        .line_to(RIGHT, y)
        .stroke();
}

fn text(content: &mut Content, x: f32, y: f32, size: f32, font: Name, color: Color, value: &str) {
    write_text(content, x, y, size, font, color, &win_ansi(value));
}

fn write_text(
    content: &mut Content,
    x: f32,
    y: f32,
    size: f32,
    font: Name,
    color: Color,
    bytes: &[u8],
) {
    let (r, g, b) = channels(color);
    content
        .set_fill_rgb(r, g, b)
        .begin_text()
        .set_font(font, size)
        .set_text_matrix([1.0, 0.0, 0.0, 1.0, x, y])
        .show(Str(bytes))
        .end_text();
}

fn win_ansi(value: &str) -> Vec<u8> {
    const EXTENDED: &str = "€\0‚ƒ„…†‡ˆ‰Š‹Œ\0Ž\0\0‘’“”•–—˜™š›œ\0žŸ";
    value
        .chars()
        .map(|c| match c {
            ' '..='~' | '\u{a0}'..='\u{ff}' => c as u8,
            c if c.is_whitespace() => b' ',
            c if c.is_control() => b'?',
            c => EXTENDED
                .chars()
                .position(|item| item == c)
                .map_or(b'?', |index| 0x80 + index as u8),
        })
        .collect()
}

fn glyph_width(byte: u8, font: Name) -> f32 {
    let metrics = if font == BOLD {
        &HELVETICA_BOLD
    } else {
        &HELVETICA
    };
    metrics[usize::from(byte.saturating_sub(b' '))] as f32
}

fn width(bytes: &[u8], size: f32, font: Name) -> f32 {
    bytes
        .iter()
        .map(|&byte| glyph_width(byte, font))
        .sum::<f32>()
        * size
        / 1000.0
}

fn wrap(value: &str, max_width: f32, size: f32, font: Name) -> Vec<Vec<u8>> {
    let limit = max_width * 1000.0 / size;
    let mut lines = Vec::new();
    let mut line = Vec::new();
    let mut used = 0.0;
    for word in value.split_whitespace().map(win_ansi) {
        let word_width: f32 = word.iter().map(|&byte| glyph_width(byte, font)).sum();
        if !line.is_empty() {
            let space = glyph_width(b' ', font);
            if used + space + word_width > limit {
                lines.push(std::mem::take(&mut line));
                used = 0.0;
            } else {
                line.push(b' ');
                used += space;
            }
        }
        // Break an identifier only when it cannot fit in an empty cell.
        for byte in word {
            let advance = glyph_width(byte, font);
            if used + advance > limit && !line.is_empty() {
                lines.push(std::mem::take(&mut line));
                used = 0.0;
            }
            line.push(byte);
            used += advance;
        }
    }
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

// Standard Helvetica glyph advances (1/1000 em), in WinAnsi byte order 32–255.
const HELVETICA: [u16; 224] = [
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556,
    556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667,
    611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667,
    667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500,
    222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
    350, 556, 350, 222, 556, 333, 1000, 556, 556, 333, 1000, 667, 333, 1000, 350, 611, 350, 350,
    222, 222, 333, 333, 350, 556, 1000, 333, 1000, 500, 333, 944, 350, 500, 667, 278, 333, 556,
    556, 556, 556, 260, 556, 333, 737, 370, 556, 584, 333, 737, 333, 400, 584, 333, 333, 333, 556,
    537, 278, 333, 333, 365, 556, 834, 834, 834, 611, 667, 667, 667, 667, 667, 667, 1000, 722, 667,
    667, 667, 667, 278, 278, 278, 278, 722, 722, 778, 778, 778, 778, 778, 584, 778, 722, 722, 722,
    722, 667, 667, 611, 556, 556, 556, 556, 556, 556, 889, 500, 556, 556, 556, 556, 278, 278, 278,
    278, 556, 556, 556, 556, 556, 556, 556, 584, 611, 556, 556, 556, 556, 500, 556, 500,
];
const HELVETICA_BOLD: [u16; 224] = [
    278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556,
    556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667,
    611, 778, 722, 278, 556, 722, 611, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667,
    667, 611, 333, 278, 333, 584, 556, 333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556,
    278, 889, 611, 611, 611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584,
    350, 556, 350, 278, 556, 500, 1000, 556, 556, 333, 1000, 667, 333, 1000, 350, 611, 350, 350,
    278, 278, 500, 500, 350, 556, 1000, 333, 1000, 556, 333, 944, 350, 500, 667, 278, 333, 556,
    556, 556, 556, 280, 556, 333, 737, 370, 556, 584, 333, 737, 333, 400, 584, 333, 333, 333, 611,
    556, 278, 333, 333, 365, 556, 834, 834, 834, 611, 722, 722, 722, 722, 722, 722, 1000, 722, 667,
    667, 667, 667, 278, 278, 278, 278, 722, 722, 778, 778, 778, 778, 778, 584, 778, 722, 722, 722,
    722, 667, 667, 611, 556, 556, 556, 556, 556, 556, 889, 556, 556, 556, 556, 556, 278, 278, 278,
    278, 611, 611, 611, 611, 611, 611, 611, 584, 611, 611, 611, 611, 611, 556, 611, 556,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Finding;

    #[test]
    fn pdf_preserves_latin_1_and_paginates() {
        let scan = Scan {
            id: "example".into(),
            reference: "docker.io/library/alpine:3".into(),
            platform: "linux/amd64".into(),
            status: "completed".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            finished_at: None,
            source: "import".into(),
            error: None,
            counts: None,
        };
        let mut report = Report {
            scanners: vec![],
            evidence_available: None,
            packages: vec![],
            findings: vec![],
            inventory_available: false,
            digest: None,
            observation_complete: None,
            counts: Default::default(),
            checks: vec![],
            size_bytes: None,
            os: None,
        };
        let branding = Branding {
            organization: "Équipe Peñón Zürich".into(),
            ..Branding::default()
        };
        let first = build(&scan, &report, &branding, "Trivy").unwrap();
        assert!(first.starts_with(b"%PDF"));
        assert!(
            first
                .windows(b"/Count 1".len())
                .any(|part| part == b"/Count 1")
        );
        let encoded = win_ansi(&branding.organization);
        assert_eq!(encoded, b"\xc9quipe Pe\xf1\xf3n Z\xfcrich");
        // pdf-writer serializes non-ASCII strings as hex.
        let hex = b"<C97175697065205065F1F36E205AFC72696368>";
        assert!(first.windows(hex.len()).any(|part| part == hex));

        report.findings = (0..120)
            .map(|i| Finding {
                aliases: vec![],
                detected_by: vec![],
                id: format!("CVE-2026-{i:04}"),
                package: "container-library".into(),
                ecosystem: "alpine".into(),
                installed: "1.2.3-r0".into(),
                fixed: "1.2.3-r1".into(),
                severity: "HIGH".into(),
                title: "A long wrapped vulnerability title ".repeat(4),
                purl: None,
            })
            .collect();
        let pdf = build(&scan, &report, &branding, "Trivy").unwrap();
        let headers = pdf
            .windows(b"(Advisory ID)".len())
            .filter(|part| *part == b"(Advisory ID)")
            .count();
        assert!(
            headers > 3,
            "findings table header should repeat across pages"
        );
        let label = format!("(Page 1 of {headers})");
        assert!(
            pdf.windows(label.len())
                .any(|part| part == label.as_bytes())
        );
    }

    #[test]
    fn wraps_using_glyph_widths_and_splits_long_identifiers() {
        let lines = wrap("wide words and éÉüüññññññññññññ", 26.0, BODY_SIZE, REGULAR);
        assert!(lines.len() > 3);
        assert!(
            lines
                .iter()
                .all(|line| width(line, BODY_SIZE, REGULAR) <= 26.0)
        );
        assert!(width(b"WWW", BODY_SIZE, REGULAR) > width(b"iii", BODY_SIZE, REGULAR));
    }
}
