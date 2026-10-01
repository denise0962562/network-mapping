//! Application calendar rules. Instants and elapsed durations always remain UTC.
use std::sync::{OnceLock, RwLock};

use chrono::{DateTime, Duration, LocalResult, NaiveDateTime, Offset, TimeZone, Utc};
use chrono_tz::{OffsetComponents, Tz};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};

pub const DEFAULT_TIMEZONE: &str = "Asia/Shanghai";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GeneralSettings {
    pub timezone: String,
    pub hour_cycle: String,
    pub date_format: String,
}

impl Default for GeneralSettings {
    fn default() -> Self {
        Self {
            timezone: DEFAULT_TIMEZONE.into(),
            hour_cycle: "24".into(),
            date_format: "YYYY-MM-DD".into(),
        }
    }
}

impl GeneralSettings {
    pub fn validate(&self) -> Result<(), String> {
        self.timezone
            .parse::<Tz>()
            .map_err(|_| "请选择有效的 IANA 时区".to_owned())?;
        if !matches!(self.hour_cycle.as_str(), "12" | "24") {
            return Err("时间制式必须为 12 或 24".into());
        }
        if !matches!(
            self.date_format.as_str(),
            "YYYY-MM-DD" | "YYYY/MM/DD" | "DD/MM/YYYY"
        ) {
            return Err("不支持的日期格式".into());
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct TimeSettings {
    pub document: GeneralSettings,
    pub revision: i64,
}

static SETTINGS: OnceLock<RwLock<TimeSettings>> = OnceLock::new();
fn state() -> &'static RwLock<TimeSettings> {
    SETTINGS.get_or_init(|| {
        RwLock::new(TimeSettings {
            document: GeneralSettings::default(),
            revision: 0,
        })
    })
}
pub fn snapshot() -> TimeSettings {
    state().read().unwrap_or_else(|e| e.into_inner()).clone()
}
pub fn apply(document: GeneralSettings, revision: i64) {
    let mut current = state().write().unwrap_or_else(|e| e.into_inner());
    if revision >= current.revision {
        *current = TimeSettings { document, revision };
    }
}
pub fn timezone() -> Tz {
    snapshot()
        .document
        .timezone
        .parse()
        .unwrap_or(chrono_tz::Asia::Shanghai)
}
pub fn format_now() -> String {
    format_instant(Utc::now())
}
pub fn format_instant(instant: DateTime<Utc>) -> String {
    let settings = snapshot();
    let tz = settings
        .document
        .timezone
        .parse::<Tz>()
        .unwrap_or(chrono_tz::Asia::Shanghai);
    let date = match settings.document.date_format.as_str() {
        "YYYY/MM/DD" => "%Y/%m/%d",
        "DD/MM/YYYY" => "%d/%m/%Y",
        _ => "%Y-%m-%d",
    };
    let time = if settings.document.hour_cycle == "12" {
        "%I:%M:%S %p"
    } else {
        "%H:%M:%S"
    };
    format!(
        "{} {}",
        instant
            .with_timezone(&tz)
            .format(&format!("{date} {time} %:z")),
        tz.name()
    )
}

/// Scheduled calendar times: choose the first occurrence, or advance over a clock gap.
pub fn scheduled_time(tz: Tz, local: NaiveDateTime) -> Result<DateTime<Utc>, String> {
    for minute in 0..=1440 {
        let candidate = local
            .checked_add_signed(Duration::minutes(minute))
            .ok_or("时间超出范围")?;
        match tz.from_local_datetime(&candidate) {
            LocalResult::Single(t) => return Ok(t.with_timezone(&Utc)),
            LocalResult::Ambiguous(a, b) => return Ok(a.min(b).with_timezone(&Utc)),
            LocalResult::None => {}
        }
    }
    Err("所选时区没有有效的日历时间".into())
}

pub async fn refresh(pool: &Pool) -> Result<TimeSettings, String> {
    let client = pool.get().await.map_err(|e| e.to_string())?;
    let row = client
        .query_one(
            "SELECT document, revision FROM runtime_configuration WHERE namespace = 'general';",
            &[],
        )
        .await
        .map_err(|e| e.to_string())?;
    let document: GeneralSettings =
        serde_json::from_value(row.get("document")).map_err(|e| e.to_string())?;
    document.validate()?;
    apply(document, row.get("revision"));
    Ok(snapshot())
}

pub fn timezone_options() -> Vec<serde_json::Value> {
    let now = Utc::now();
    chrono_tz::TZ_VARIANTS.iter().map(|tz| {
        let current = now.with_timezone(tz);
        // Inspect the whole current year, including southern-hemisphere transitions.
        let year: String = now.format("%Y").to_string();
        let has_dst = (1..=12).any(|month| {
            chrono::NaiveDate::parse_from_str(&format!("{year}-{month:02}-15"), "%Y-%m-%d")
                .ok().and_then(|d| d.and_hms_opt(12, 0, 0))
                .and_then(|d| tz.from_local_datetime(&d).earliest())
                .is_some_and(|d| d.offset().dst_offset() != Duration::zero())
        });
        serde_json::json!({"id": tz.name(), "offsetSeconds": current.offset().fix().local_minus_utc(), "observesDst": has_dst})
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn local(s: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M").expect("date")
    }
    #[test]
    fn shanghai_has_same_offset_in_winter_and_summer() {
        let tz = chrono_tz::Asia::Shanghai;
        for date in ["2026-01-15 09:00", "2026-07-15 09:00"] {
            let t = scheduled_time(tz, local(date)).expect("time");
            assert_eq!(t.format("%H:%M").to_string(), "01:00");
        }
    }
    #[test]
    fn new_york_schedule_handles_gaps_and_repeated_times() {
        let tz = chrono_tz::America::New_York;
        assert_eq!(
            scheduled_time(tz, local("2026-03-08 02:30"))
                .expect("gap")
                .to_rfc3339(),
            "2026-03-08T07:00:00+00:00"
        );
        assert_eq!(
            scheduled_time(tz, local("2026-11-01 01:30"))
                .expect("repeat")
                .to_rfc3339(),
            "2026-11-01T05:30:00+00:00"
        );
    }
    #[test]
    fn settings_reject_offsets_and_invalid_formats() {
        let mut settings = GeneralSettings {
            timezone: "+08:00".into(),
            ..GeneralSettings::default()
        };
        assert!(settings.validate().is_err());
        settings.timezone = "UTC".into();
        assert!(settings.validate().is_ok());
        settings.date_format = "%n".into();
        assert!(settings.validate().is_err());
    }
}
