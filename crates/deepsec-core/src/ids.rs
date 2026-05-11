use time::OffsetDateTime;
use time::format_description::well_known::Iso8601;

/// Run IDs are `YYYYMMDDHHMMSS-<4-hex>` — same shape as the TS CLI.
pub fn generate_run_id() -> String {
    let now = OffsetDateTime::now_utc();
    let stamp = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
    );
    let suffix: String = (0..4)
        .map(|_| {
            let n = fastrand::u8(0..16);
            std::char::from_digit(n as u32, 16).unwrap()
        })
        .collect();
    format!("{stamp}-{suffix}")
}

pub fn now_iso() -> String {
    OffsetDateTime::now_utc()
        .format(&Iso8601::DEFAULT)
        .unwrap_or_default()
}
