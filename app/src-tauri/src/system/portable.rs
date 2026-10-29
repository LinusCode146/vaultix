//! The Trash and QR codes on Windows, Linux and Android, with portable crates.

use std::path::Path;

/// Move a file to the Recycle Bin (Windows) or the desktop's trash (Linux).
#[cfg(desktop)]
pub fn trash(path: &Path) -> Result<(), String> {
    trash::delete(path).map_err(|_| format!("Couldn't move {} to the trash.", path.display()))
}

/// Android has no trash; nothing on the phone offers it.
#[cfg(mobile)]
pub fn trash(path: &Path) -> Result<(), String> {
    Err(format!("Couldn't remove {}.", path.display()))
}

/// On a phone, codes are scanned with the camera instead (in the UI).
#[cfg(mobile)]
pub fn scan_screen_qr() -> Result<String, String> {
    Err("qr-screen-unavailable".into())
}

/// The `otpauth://` URI in a two-factor QR code on screen. Blocks while the
/// screens are captured; call it off the main thread.
#[cfg(windows)]
pub fn scan_screen_qr() -> Result<String, String> {
    let monitors = xcap::Monitor::all().map_err(|_| "qr-screen-unavailable".to_string())?;
    let mut payloads = Vec::new();
    for monitor in monitors {
        let image = monitor.capture_image().map_err(|_| "qr-screen-unavailable".to_string())?;
        payloads.extend(decode(image::DynamicImage::ImageRgba8(image).to_luma8()));
    }
    pick(payloads)
}

/// The `otpauth://` URI in a two-factor QR code on screen, from a screenshot
/// taken through the desktop portal (X11 and Wayland; the desktop may ask
/// first). Blocks until it's taken; call it off the main thread.
#[cfg(target_os = "linux")]
pub fn scan_screen_qr() -> Result<String, String> {
    let file = portal_screenshot().map_err(|e| {
        eprintln!("[vaultix] screenshot portal: {e}");
        "qr-screen-unavailable".to_string()
    })?;
    let bytes = std::fs::read(&file);
    // The desktop may have saved it among the user's pictures; it can show secrets.
    let _ = std::fs::remove_file(&file);
    let image = image::load_from_memory(&bytes.map_err(|_| "qr-failed".to_string())?).map_err(|_| "qr-failed".to_string())?;
    pick(decode(image.to_luma8()))
}

/// Ask org.freedesktop.portal.Screenshot for a non-interactive screenshot,
/// and return the file it was saved to.
#[cfg(target_os = "linux")]
fn portal_screenshot() -> Result<std::path::PathBuf, String> {
    use std::collections::HashMap;
    use zbus::blocking::{Connection, MessageIterator};
    use zbus::zvariant::{OwnedValue, Value};

    let bus = Connection::session().map_err(|e| e.to_string())?;
    // The portal answers on a Request object whose path is known in advance:
    // subscribe before asking, so the answer can't be missed.
    let token = format!("vaultix{}", std::process::id());
    let sender = bus.unique_name().ok_or("no bus name")?.trim_start_matches(':').replace('.', "_");
    let request = format!("/org/freedesktop/portal/desktop/request/{sender}/{token}");
    let rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface("org.freedesktop.portal.Request")
        .and_then(|b| b.member("Response"))
        .and_then(|b| b.path(request.as_str()))
        .map_err(|e| e.to_string())?
        .build();
    let mut responses = MessageIterator::for_match_rule(rule, &bus, Some(1)).map_err(|e| e.to_string())?;
    let options: HashMap<&str, Value> = HashMap::from([("handle_token", Value::from(token.as_str())), ("interactive", Value::from(false))]);
    bus.call_method(
        Some("org.freedesktop.portal.Desktop"),
        "/org/freedesktop/portal/desktop",
        Some("org.freedesktop.portal.Screenshot"),
        "Screenshot",
        &("", options),
    )
    .map_err(|e| e.to_string())?;
    let message = responses.next().ok_or("no answer")?.map_err(|e| e.to_string())?;
    let (status, results): (u32, HashMap<String, OwnedValue>) = message.body().deserialize().map_err(|e| e.to_string())?;
    if status != 0 {
        return Err(format!("declined ({status})"));
    }
    let uri: String = results.get("uri").and_then(|v| String::try_from(v.clone()).ok()).ok_or("no file")?;
    let path = uri.strip_prefix("file://").ok_or("not a file")?;
    // Percent-decoding: the portal escapes spaces and non-ASCII characters.
    let decoded = url::Url::parse(&format!("file://{path}")).ok().and_then(|u| u.to_file_path().ok());
    decoded.ok_or_else(|| "bad file name".into())
}

/// The `otpauth://` URI in a QR code in an image (PNG, JPEG, …).
pub fn scan_image_qr(bytes: &[u8]) -> Result<String, String> {
    let image = image::load_from_memory(bytes).map_err(|_| "qr-failed".to_string())?;
    pick(decode(image.to_luma8()))
}

fn decode(image: image::GrayImage) -> Vec<String> {
    let mut prepared = rqrr::PreparedImage::prepare(image);
    prepared.detect_grids().into_iter().filter_map(|grid| grid.decode().ok().map(|(_, text)| text)).collect()
}

/// The first two-factor setup code, or why there is none. Codes as in macos.rs.
fn pick(payloads: Vec<String>) -> Result<String, String> {
    let has = |scheme: &str| payloads.iter().find(|p| p.get(..scheme.len()).is_some_and(|s| s.eq_ignore_ascii_case(scheme)));
    if let Some(uri) = has("otpauth://") {
        return Ok(uri.clone());
    }
    Err(if has("otpauth-migration://").is_some() {
        "qr-migration"
    } else if payloads.is_empty() {
        "qr-none"
    } else {
        "qr-not-totp"
    }
    .into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_two_factor_qr_codes_from_images() {
        let uri = scan_image_qr(include_bytes!("../../test-fixtures/totp-qr.png")).unwrap();
        assert_eq!(uri, "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example");
        assert_eq!(scan_image_qr(include_bytes!("../../test-fixtures/url-qr.png")), Err("qr-not-totp".into()));
        assert_eq!(scan_image_qr(b"not an image"), Err("qr-failed".into()));
    }

    #[test]
    fn picks_the_setup_code() {
        assert_eq!(pick(vec!["https://x".into(), "OTPAUTH://totp/a?secret=A".into()]), Ok("OTPAUTH://totp/a?secret=A".into()));
        assert_eq!(pick(vec!["otpauth-migration://offline?data=x".into()]), Err("qr-migration".into()));
        assert_eq!(pick(vec![]), Err("qr-none".into()));
    }
}
