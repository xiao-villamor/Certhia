use crate::{ApiError, ApiResult, App};
use anyhow::{Result, ensure};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, put},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use jpeg_decoder::PixelFormat;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::Cursor;

const MAX_LOGO_BYTES: usize = 1024 * 1024;
const MAX_LOGO_DIMENSION: u32 = 4096;
const PNG: &str = "image/png";
const JPEG: &str = "image/jpeg";

#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Branding {
    pub organization: String,
    pub footer: String,
    pub logo: Option<Logo>,
}

impl Branding {
    pub fn organization(&self) -> &str {
        if self.organization.is_empty() {
            crate::PRODUCT_NAME
        } else {
            &self.organization
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Logo {
    pub content_type: String,
    pub data: String,
}

pub enum Pixels {
    Png {
        rgb: Vec<u8>,
        alpha: Option<Vec<u8>>,
    },
    Jpeg(PixelFormat),
}

pub struct Image {
    pub width: u32,
    pub height: u32,
    pub pixels: Pixels,
}

pub fn routes() -> Router<App> {
    Router::new()
        .route("/settings/report-branding", get(branding).put(save_text))
        .route(
            "/settings/report-branding/logo",
            get(logo).delete(remove_logo),
        )
        .route(
            "/settings/report-branding/logo",
            put(save_logo).layer(DefaultBodyLimit::max(MAX_LOGO_BYTES)),
        )
}

pub async fn load(app: &App) -> Result<Branding> {
    let value: Option<Value> =
        sqlx::query_scalar("SELECT value FROM settings WHERE key='report_branding'")
            .fetch_optional(&app.0.database.primary)
            .await?;
    Ok(value
        .map(serde_json::from_value)
        .transpose()?
        .unwrap_or_default())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Summary {
    organization: String,
    footer: String,
    has_logo: bool,
    sample_scan_id: Option<String>,
}

async fn branding(State(app): State<App>) -> ApiResult<Json<Summary>> {
    let (organization, footer, has_logo, sample_scan_id) =
        sqlx::query_as::<_, (String, String, bool, Option<String>)>(
            "SELECT coalesce(value->>'organization',''), coalesce(value->>'footer',''),
                coalesce(value ? 'logo', false),
                (SELECT id::text FROM scans WHERE status='completed'
                 ORDER BY coalesce(finished_at, queued_at) DESC, id DESC LIMIT 1)
             FROM (SELECT 1) AS workspace
             LEFT JOIN settings ON key='report_branding'",
        )
        .fetch_one(&app.0.database.primary)
        .await?;
    Ok(Json(Summary {
        organization,
        footer,
        has_logo,
        sample_scan_id,
    }))
}

async fn merge(app: &App, patch: Value) -> ApiResult<()> {
    sqlx::query(
        "INSERT INTO settings(key,value) VALUES ('report_branding',$1)
        ON CONFLICT (key) DO UPDATE SET value=settings.value || EXCLUDED.value",
    )
    .bind(patch)
    .execute(&app.0.database.primary)
    .await?;
    Ok(())
}

#[derive(Deserialize)]
struct ReportText {
    organization: String,
    #[serde(default)]
    footer: String,
}

async fn save_text(
    State(app): State<App>,
    Json(input): Json<ReportText>,
) -> ApiResult<Json<Summary>> {
    let organization = input.organization.trim();
    let footer = input.footer.trim();
    if organization.chars().count() > 100 || footer.chars().count() > 200 {
        return Err(ApiError::bad(
            "Use up to 100 characters for the organization and 200 for the footer.",
        ));
    }
    if organization
        .chars()
        .chain(footer.chars())
        .any(char::is_control)
    {
        return Err(ApiError::bad(
            "Enter the organization and footer as single lines.",
        ));
    }
    merge(
        &app,
        json!({ "organization": organization, "footer": footer }),
    )
    .await?;
    app.0
        .database
        .audit("report_branding.updated", "instance", "")
        .await?;
    branding(State(app)).await
}

async fn save_logo(
    State(app): State<App>,
    headers: HeaderMap,
    bytes: Bytes,
) -> ApiResult<StatusCode> {
    let content_type = match headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
    {
        Some(PNG) => PNG,
        Some(JPEG) => JPEG,
        _ => {
            return Err(ApiError(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Choose a PNG or JPEG logo.".into(),
            ));
        }
    };
    let logo = tokio::task::spawn_blocking(move || {
        decode_logo(content_type, &bytes).map_err(ApiError::bad)?;
        Ok::<_, ApiError>(Logo {
            content_type: content_type.to_owned(),
            data: STANDARD.encode(bytes),
        })
    })
    .await
    .map_err(anyhow::Error::from)??;
    merge(&app, json!({ "logo": logo })).await?;
    app.0
        .database
        .audit("report_branding.logo_uploaded", "instance", content_type)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_logo(State(app): State<App>) -> ApiResult<StatusCode> {
    let result = sqlx::query(
        "UPDATE settings SET value=value-'logo' WHERE key='report_branding' AND value ? 'logo'",
    )
    .execute(&app.0.database.primary)
    .await?;
    if result.rows_affected() > 0 {
        app.0
            .database
            .audit("report_branding.logo_removed", "instance", "")
            .await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn logo(State(app): State<App>) -> ApiResult<Response> {
    let logo = load(&app)
        .await?
        .logo
        .ok_or_else(|| ApiError::missing("No report logo has been uploaded."))?;
    let bytes = STANDARD.decode(logo.data).map_err(anyhow::Error::from)?;
    Ok((
        [
            (header::CONTENT_TYPE, logo.content_type),
            (header::CACHE_CONTROL, "no-store".into()),
        ],
        bytes,
    )
        .into_response())
}

pub fn decode_logo(content_type: &str, bytes: &[u8]) -> Result<Image> {
    ensure!(
        bytes.len() <= MAX_LOGO_BYTES,
        "The report logo must be 1 MB or smaller."
    );
    match content_type {
        PNG if bytes.starts_with(b"\x89PNG\r\n\x1a\n") => {
            decode_png(bytes).map_err(|error| anyhow::anyhow!("Invalid PNG logo: {error}"))
        }
        JPEG if bytes.starts_with(b"\xff\xd8\xff") => {
            decode_jpeg(bytes).map_err(|error| anyhow::anyhow!("Invalid JPEG logo: {error}"))
        }
        _ => anyhow::bail!("The file must be a PNG or JPEG matching its content type."),
    }
}

fn check_dimensions(width: u32, height: u32) -> Result<()> {
    ensure!(
        (1..=MAX_LOGO_DIMENSION).contains(&width) && (1..=MAX_LOGO_DIMENSION).contains(&height),
        "Use a logo no larger than 4096 × 4096 pixels."
    );
    Ok(())
}

fn decode_png(bytes: &[u8]) -> Result<Image> {
    use png::ColorType::*;
    let mut decoder = png::Decoder::new(Cursor::new(bytes));
    decoder.set_transformations(png::Transformations::normalize_to_color8());
    let info = decoder.read_header_info()?;
    check_dimensions(info.width, info.height)?;
    let mut reader = decoder.read_info()?;
    let mut buffer = vec![
        0;
        reader
            .output_buffer_size()
            .ok_or_else(|| anyhow::anyhow!("Invalid pixel dimensions."))?
    ];
    let frame = reader.next_frame(&mut buffer)?;
    reader.finish()?;
    buffer.truncate(frame.buffer_size());
    let pixels = buffer.chunks_exact(frame.color_type.samples());
    let mut alpha = matches!(frame.color_type, Rgba | GrayscaleAlpha).then(Vec::new);
    let rgb = if frame.color_type == Rgb {
        buffer
    } else {
        ensure!(
            frame.color_type != Indexed,
            "The PNG palette could not be decoded."
        );
        let mut rgb = Vec::with_capacity(pixels.len() * 3);
        for pixel in pixels {
            match frame.color_type {
                Grayscale | GrayscaleAlpha => rgb.extend_from_slice(&[pixel[0]; 3]),
                _ => rgb.extend_from_slice(&pixel[..3]),
            }
            if let Some(alpha) = &mut alpha {
                alpha.push(pixel[pixel.len() - 1]);
            }
        }
        rgb
    };
    Ok(Image {
        width: frame.width,
        height: frame.height,
        pixels: Pixels::Png { rgb, alpha },
    })
}

fn decode_jpeg(bytes: &[u8]) -> Result<Image> {
    let mut decoder = jpeg_decoder::Decoder::new(Cursor::new(bytes));
    decoder.set_max_decoding_buffer_size((MAX_LOGO_DIMENSION as usize).pow(2) * 4);
    decoder.read_info()?;
    let info = decoder
        .info()
        .ok_or_else(|| anyhow::anyhow!("Missing image metadata."))?;
    let (width, height) = (u32::from(info.width), u32::from(info.height));
    check_dimensions(width, height)?;
    ensure!(
        info.pixel_format != PixelFormat::L16,
        "Use an 8-bit JPEG logo."
    );
    decoder.decode()?;
    Ok(Image {
        width,
        height,
        pixels: Pixels::Jpeg(info.pixel_format),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_logo_content_and_oversize() {
        assert!(decode_logo(PNG, b"<svg/>").is_err());
        assert!(decode_logo(PNG, b"\x89PNG\r\n\x1a\n").is_err());
        assert!(decode_logo(PNG, b"\xff\xd8\xff").is_err());
        assert!(decode_logo(JPEG, b"\xff\xd8\xff").is_err());
        assert!(
            decode_logo(JPEG, &vec![0; MAX_LOGO_BYTES + 1])
                .err()
                .unwrap()
                .to_string()
                .contains("1 MB")
        );
    }

    #[test]
    fn decodes_transparent_png() {
        let mut bytes = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut bytes, 1, 1);
            encoder.set_color(png::ColorType::Rgba);
            encoder
                .write_header()
                .unwrap()
                .write_image_data(&[15, 30, 60, 100])
                .unwrap();
        }
        let image = decode_logo(PNG, &bytes).unwrap();
        assert_eq!((image.width, image.height), (1, 1));
        let Pixels::Png { rgb, alpha } = image.pixels else {
            panic!("Expected PNG pixels");
        };
        assert_eq!(rgb, [15, 30, 60]);
        assert_eq!(alpha.unwrap(), [100]);
    }
}
