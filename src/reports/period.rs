use chrono::{DateTime, Datelike, Days, FixedOffset, Months, NaiveDate, TimeZone, Utc};
use serde::{Deserialize, Serialize};

pub const TIMEZONE: &str = "Asia/Shanghai";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PeriodType {
    Weekly,
    Monthly,
}

impl PeriodType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Weekly => "weekly",
            Self::Monthly => "monthly",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Weekly => "周报",
            Self::Monthly => "月报",
        }
    }
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "weekly" => Ok(Self::Weekly),
            "monthly" => Ok(Self::Monthly),
            _ => Err("周期必须为 weekly 或 monthly".into()),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Period {
    pub kind: PeriodType,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

fn offset() -> Result<FixedOffset, String> {
    FixedOffset::east_opt(8 * 3600).ok_or_else(|| "无效报告时区".into())
}

pub fn local_date(value: DateTime<Utc>) -> Result<NaiveDate, String> {
    Ok(value.with_timezone(&offset()?).date_naive())
}

pub fn local_time(date: NaiveDate, hour: u32, minute: u32) -> Result<DateTime<Utc>, String> {
    let naive = date.and_hms_opt(hour, minute, 0).ok_or("无效发送时间")?;
    offset()?
        .from_local_datetime(&naive)
        .single()
        .map(|d| d.with_timezone(&Utc))
        .ok_or_else(|| "无效报告时间".into())
}

impl Period {
    pub fn containing(kind: PeriodType, date: NaiveDate) -> Result<Self, String> {
        let start = match kind {
            PeriodType::Weekly => {
                date.checked_sub_days(Days::new(u64::from(date.weekday().num_days_from_monday())))
            }
            PeriodType::Monthly => NaiveDate::from_ymd_opt(date.year(), date.month(), 1),
        }
        .ok_or("日期超出支持范围")?;
        let end = match kind {
            PeriodType::Weekly => start.checked_add_days(Days::new(7)),
            PeriodType::Monthly => start.checked_add_months(Months::new(1)),
        }
        .ok_or("日期超出支持范围")?;
        Ok(Self {
            kind,
            start: local_time(start, 0, 0)?,
            end: local_time(end, 0, 0)?,
        })
    }
    pub fn previous(&self) -> Result<Self, String> {
        let day = local_date(self.start)?
            .checked_sub_days(Days::new(1))
            .ok_or("日期超出支持范围")?;
        Self::containing(self.kind, day)
    }
    pub fn last_closed(kind: PeriodType, now: DateTime<Utc>) -> Result<Self, String> {
        Self::containing(kind, local_date(now)?)?.previous()
    }
    pub fn validate_closed(&self, now: DateTime<Utc>) -> Result<(), String> {
        if self.end > now {
            return Err("只能生成已结束的完整周期".into());
        }
        if self.start < now - chrono::Duration::days(366) {
            return Err("仅支持最近一年内的报告".into());
        }
        Ok(())
    }
    pub fn due_at(&self, hour: u32, minute: u32) -> Result<DateTime<Utc>, String> {
        local_time(local_date(self.end)?, hour, minute)
    }
}

pub fn growth(current: f64, previous: f64) -> Option<f64> {
    (previous > 0.0).then(|| ((current - previous) / previous * 1000.0).round() / 10.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn date(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").expect("test date")
    }
    #[test]
    fn weekly_crosses_calendar_year_at_shanghai_midnight() {
        let p = Period::containing(PeriodType::Weekly, date("2026-01-01")).expect("period");
        assert_eq!(p.start.to_rfc3339(), "2025-12-28T16:00:00+00:00");
        assert_eq!(p.end.to_rfc3339(), "2026-01-04T16:00:00+00:00");
    }
    #[test]
    fn monthly_respects_leap_february_and_previous_year() {
        let p = Period::containing(PeriodType::Monthly, date("2024-02-15")).expect("period");
        assert_eq!((p.end - p.start).num_days(), 29);
        let january = Period::containing(PeriodType::Monthly, date("2026-01-15")).expect("period");
        assert_eq!(
            local_date(january.previous().expect("previous").start).expect("date"),
            date("2025-12-01")
        );
    }
    #[test]
    fn schedule_uses_local_send_time_and_closed_period() {
        let now = DateTime::parse_from_rfc3339("2026-09-28T09:00:00+08:00")
            .expect("now")
            .with_timezone(&Utc);
        let p = Period::last_closed(PeriodType::Weekly, now).expect("period");
        assert_eq!(p.due_at(9, 0).expect("due"), now);
        assert!(p.validate_closed(now).is_ok());
        assert!(
            Period::containing(PeriodType::Weekly, date("2026-09-28"))
                .expect("current")
                .validate_closed(now)
                .is_err()
        );
    }
    #[test]
    fn zero_baseline_is_not_an_infinite_growth_rate() {
        assert_eq!(growth(10.0, 0.0), None);
        assert_eq!(growth(110.0, 100.0), Some(10.0));
    }
}
