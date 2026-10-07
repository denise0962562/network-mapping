use chrono::{DateTime, Duration as ChronoDuration, Utc};
use deadpool_postgres::Pool;
use serde_json::Value;
use tokio::time::{Duration, Instant};
use tokio_postgres::IsolationLevel;
use tracing::warn;
use uuid::Uuid;

use super::{
    period::{Period, PeriodType},
    statistics, storage,
};
use crate::{
    admin::get_mail_settings_from_database, config::AnalyticsSnapshotConfig, mail_template,
    runtime_config::RuntimeConfig, system_maintenance::SystemMaintenanceState,
};

pub async fn run_worker(
    pool: Pool,
    encryption_key: String,
    analytics: RuntimeConfig<AnalyticsSnapshotConfig>,
    maintenance: actix_web::web::Data<SystemMaintenanceState>,
) {
    let mut next_schedule = Instant::now();
    loop {
        if !maintenance.snapshot().await.enabled {
            if Instant::now() >= next_schedule {
                if analytics.get().await.value.mode.runs_worker()
                    && let Err(error) = schedule(&pool).await
                {
                    warn!(event = "ReportScheduleFailed", %error);
                }
                next_schedule = Instant::now() + Duration::from_secs(60);
            }
            if let Err(error) = process_one(&pool, &analytics).await {
                warn!(event = "ReportGenerationFailed", %error);
            }
            if let Err(error) = send_one(&pool, &encryption_key).await {
                warn!(event = "ReportDeliveryFailed", %error);
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

pub(crate) async fn schedule(pool: &Pool) -> Result<(), String> {
    let settings = get_mail_settings_from_database(pool)
        .await
        .map_err(|e| e.to_string())?;
    let client = pool.get().await.map_err(|e| e.to_string())?;
    let rows = client
        .query("SELECT * FROM report_schedule WHERE enabled;", &[])
        .await
        .map_err(|e| e.to_string())?;
    drop(client);
    let calendar = crate::system_time::refresh(pool).await?;
    let timezone = calendar.document.timezone;
    let tz = timezone
        .parse::<chrono_tz::Tz>()
        .map_err(|e| e.to_string())?;
    let now = Utc::now();
    for row in rows {
        let kind = PeriodType::parse(&row.get::<_, String>("period_type"))?;
        let notify = match kind {
            PeriodType::Weekly => settings.notification_prefs.report_weekly,
            PeriodType::Monthly => settings.notification_prefs.report_monthly,
        };
        if !notify {
            continue;
        }
        let start: DateTime<Utc> = row
            .get::<_, Option<DateTime<Utc>>>("last_period_end")
            .or(row.get("enabled_at"))
            .unwrap_or(now);
        let hour = row.get::<_, i16>("send_hour") as u32;
        let minute = row.get::<_, i16>("send_minute") as u32;
        // Bounded catch-up: at most eight periods per plan and tick, never send pre-activation history.
        let mut period = if start < now - ChronoDuration::days(366) {
            Period::containing_in(
                kind,
                now.with_timezone(&tz).date_naive(),
                &timezone,
                calendar.revision,
            )?
            .previous()?
        } else {
            Period::containing_in(
                kind,
                start.with_timezone(&tz).date_naive(),
                &timezone,
                calendar.revision,
            )?
        };
        for _ in 0..8 {
            if period.due_at(hour, minute)? > now {
                break;
            }
            storage::create(pool, &period, None, "automatic", None).await?;
            period = Period::containing_in(
                kind,
                period.date(period.end)?,
                &timezone,
                calendar.revision,
            )?;
        }
    }
    Ok(())
}

pub(crate) async fn process_one(
    pool: &Pool,
    analytics: &RuntimeConfig<AnalyticsSnapshotConfig>,
) -> Result<bool, String> {
    let client = pool.get().await.map_err(|e| e.to_string())?;
    client.execute("UPDATE report_job SET status = 'retry_wait', available_at = NOW(), claim_token = NULL, lease_until = NULL \
        WHERE status = 'running' AND lease_until < NOW();", &[]).await.map_err(|e| e.to_string())?;
    let token = Uuid::new_v4();
    let row = client.query_opt("WITH picked AS (SELECT report_id FROM report_job WHERE status IN ('pending','retry_wait') AND available_at <= NOW() \
        ORDER BY available_at, report_id LIMIT 1 FOR UPDATE SKIP LOCKED) \
        UPDATE report_job j SET status = 'running', claim_token = $1, lease_until = NOW() + INTERVAL '5 minutes', attempts = attempts + 1 \
        FROM picked WHERE j.report_id = picked.report_id RETURNING j.report_id, j.attempts;", &[&token]).await.map_err(|e| e.to_string())?;
    let Some(row) = row else {
        return Ok(false);
    };
    let id: Uuid = row.get("report_id");
    let attempts: i32 = row.get("attempts");
    client.execute("UPDATE report_run SET status = 'generating' WHERE id = $1 AND status <> 'ready' AND EXISTS (SELECT 1 FROM report_job WHERE report_id = $1 AND claim_token = $2);", &[&id, &token]).await.map_err(|e| e.to_string())?;
    drop(client);
    let mode_ready = analytics.get().await.value.mode.runs_worker();
    let result = match tokio::time::timeout(
        Duration::from_secs(50),
        generate(pool, id, token, mode_ready),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err("报告生成超时，请检查数据库负载".into()),
    };
    if let Err(error) = result {
        let mut client = pool.get().await.map_err(|e| e.to_string())?;
        let tx = client.transaction().await.map_err(|e| e.to_string())?;
        let failed = attempts >= 5;
        let changed = tx.execute("UPDATE report_job SET status = $3, available_at = NOW() + $4::BIGINT * INTERVAL '1 second', \
            last_error = $5, claim_token = NULL, lease_until = NULL WHERE report_id = $1 AND claim_token = $2;",
            &[&id, &token, &if failed { "failed" } else { "retry_wait" }, &(60_i64 * i64::from(attempts.min(5))), &error]).await.map_err(|e| e.to_string())?;
        if changed > 0 {
            tx.execute("UPDATE report_run SET status = $2, last_error = $3 WHERE id = $1 AND status <> 'ready';", &[&id, &if failed { "failed" } else { "queued" }, &error]).await.map_err(|e| e.to_string())?;
        }
        tx.commit().await.map_err(|e| e.to_string())?;
    }
    Ok(true)
}

async fn generate(pool: &Pool, id: Uuid, token: Uuid, mode_ready: bool) -> Result<(), String> {
    let mut client = pool.get().await.map_err(|e| e.to_string())?;
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::RepeatableRead)
        .start()
        .await
        .map_err(|e| e.to_string())?;
    tx.batch_execute("SET LOCAL statement_timeout = '30s';")
        .await
        .map_err(|e| e.to_string())?;
    let claim = tx.query_opt("SELECT report_id, wait_deadline FROM report_job WHERE report_id = $1 AND claim_token = $2 AND status = 'running' AND lease_until > NOW() FOR UPDATE;", &[&id, &token]).await.map_err(|e| e.to_string())?;
    let Some(claim) = claim else {
        return Ok(());
    };
    let row = tx
        .query_one("SELECT * FROM report_run WHERE id = $1 FOR UPDATE;", &[&id])
        .await
        .map_err(|e| e.to_string())?;
    let mut quality = statistics::quality(&tx, id).await?;
    let current = &quality["current"];
    if current["expected"] != current["ready"]
        || (!mode_ready && current["expected"].as_i64().unwrap_or(0) > 0)
    {
        let deadline: DateTime<Utc> = claim.get("wait_deadline");
        let permanent = current["deleted"].as_i64().unwrap_or(0) > 0 || Utc::now() > deadline;
        let error = if current["deleted"].as_i64().unwrap_or(0) > 0 {
            "固定输入中的扫描执行已被删除，请生成修订版"
        } else if !mode_ready {
            "统计快照未启用，请将分析快照模式设置为 shadow 或 snapshot"
        } else if permanent {
            "统计快照等待已超过 24 小时，请检查回填任务后重试"
        } else {
            "等待扫描统计完整：请检查分析快照进度"
        };
        tx.execute(
            "UPDATE report_run SET status = $2, quality = $3, last_error = $4 WHERE id = $1;",
            &[
                &id,
                &if permanent { "failed" } else { "waiting_data" },
                &quality,
                &error,
            ],
        )
        .await
        .map_err(|e| e.to_string())?;
        tx.execute("UPDATE report_job SET status = $3, available_at = NOW() + INTERVAL '1 minute', attempts = 0, claim_token = NULL, lease_until = NULL, last_error = $4 \
            WHERE report_id = $1 AND claim_token = $2;", &[&id, &token, &if permanent { "failed" } else { "retry_wait" }, &error]).await.map_err(|e| e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())?;
        return Ok(());
    }
    let period = Period {
        timezone: row.get("timezone"),
        settings_revision: row.get("settings_revision"),
        kind: PeriodType::parse(&row.get::<_, String>("period_type"))?,
        start: row.get("period_start"),
        end: row.get("period_end"),
    };
    let snapshot: Value = row.get("task_snapshot");
    let payload = statistics::build(&tx, id, &period, &snapshot, &quality).await?;
    let checksum = openssl::hash::hash(
        openssl::hash::MessageDigest::sha256(),
        &serde_json::to_vec(&payload).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?
    .iter()
    .map(|b| format!("{b:02x}"))
    .collect::<String>();
    let key = if period.kind == PeriodType::Weekly {
        mail_template::REPORT_WEEKLY_TEMPLATE_KEY
    } else {
        mail_template::REPORT_MONTHLY_TEMPLATE_KEY
    };
    let mail_settings = match super::mail_config::load(&tx).await {
        Ok(settings) => settings,
        Err(error) => {
            quality["mail_error"] = serde_json::json!(error);
            Default::default()
        }
    };
    let generated_at: DateTime<Utc> = tx
        .query_one("SELECT NOW() AS at", &[])
        .await
        .map_err(|e| e.to_string())?
        .get("at");
    let metadata = super::mail_context::MailMetadata {
        revision: row.get("revision"),
        generated_at,
        cutoff_at: row.get("cutoff_at"),
    };
    let image = if mail_settings.remote_images_enabled {
        let trend = serde_json::from_value::<Vec<super::chart::TrendDay>>(payload["trend"].clone())
            .map_err(|e| e.to_string())?;
        super::chart::render_async(trend).await
    } else {
        Ok(Vec::new())
    };
    let image_url = match image {
        Ok(bytes) if !bytes.is_empty() => {
            super::assets::create(&tx, id, &bytes, &mail_settings, generated_at).await?
        }
        Ok(_) => String::new(),
        Err(error) => {
            quality["mail_error"] = serde_json::json!(error);
            String::new()
        }
    };
    let mail = if quality.get("mail_error").is_some() {
        Ok((None, 0))
    } else {
        let context = tera::Context::from_serialize(super::mail_context::build(
            &payload,
            &quality,
            id,
            &metadata,
            &mail_settings,
            &image_url,
        )?)
        .map_err(|e| e.to_string())?;
        mail_template::render_report(&tx, key, &context).await
    };
    let (rendered, version) = match mail {
        Ok(value) => value,
        Err(error) => {
            quality["mail_error"] = serde_json::json!(error);
            (None, 0)
        }
    };
    if rendered.is_none() && quality.get("mail_error").is_none() {
        quality["mail_error"] = serde_json::json!("报告邮件模板已停用");
    }
    // Published legacy templates may intentionally omit the image variable.
    // Keep access state only when the archived mail actually refers to the asset.
    if rendered.as_ref().is_none_or(|mail| {
        image_url.is_empty()
            || (!mail.html_body.contains(&image_url) && !mail.text_body.contains(&image_url))
    }) {
        tx.execute("DELETE FROM report_mail_asset WHERE report_id = $1", &[&id])
            .await
            .map_err(|e| e.to_string())?;
    }
    let rendered = rendered
        .map(serde_json::to_value)
        .transpose()
        .map_err(|e| e.to_string())?;
    tx.execute("UPDATE report_run SET status = 'ready', payload = $2, quality = $3, generated_at = $8, last_error = NULL, \
        content_checksum = $4, template_key = $5, template_version = $6, rendered_mail = $7 WHERE id = $1;",
        &[&id, &payload, &quality, &checksum, &key, &version, &rendered, &generated_at]).await.map_err(|e| e.to_string())?;
    if row.get::<_, bool>("send_email") {
        let selected: Vec<i32> = row.get("recipient_ids");
        storage::enqueue_delivery(&tx, id, &selected, true, false).await?;
    }
    tx.execute("UPDATE report_job SET status = 'succeeded', claim_token = NULL, lease_until = NULL, last_error = NULL WHERE report_id = $1 AND claim_token = $2;", &[&id, &token]).await.map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(())
}

pub(crate) async fn send_one(pool: &Pool, encryption_key: &str) -> Result<bool, String> {
    let client = pool.get().await.map_err(|e| e.to_string())?;
    let token = Uuid::new_v4();
    let row = client.query_opt("WITH picked AS (SELECT id FROM report_delivery WHERE (status = 'pending' AND available_at <= NOW()) \
        OR (status = 'sending' AND lease_until < NOW()) ORDER BY available_at, id LIMIT 1 FOR UPDATE SKIP LOCKED) \
        UPDATE report_delivery d SET status = 'sending', claim_token = $1, lease_until = NOW() + INTERVAL '5 minutes', attempts = attempts + 1 \
        FROM picked WHERE d.id = picked.id RETURNING d.*;", &[&token]).await.map_err(|e| e.to_string())?;
    let Some(row) = row else {
        return Ok(false);
    };
    let id: Uuid = row.get("id");
    let report: Uuid = row.get("report_id");
    let user: i32 = row.get("recipient_user_id");
    let email: String = row.get("recipient");
    let attempts: i32 = row.get("attempts");
    let automatic: bool = row.get("automatic");
    let report = client.query_one("SELECT r.rendered_mail, r.period_type, r.period_end, s.enabled, s.enabled_at, s.recipient_ids, \
        NOT EXISTS (SELECT 1 FROM report_mail_asset a WHERE a.report_id = r.id AND (a.revoked_at IS NOT NULL OR a.expires_at <= NOW())) AS image_available, COALESCE((SELECT enabled FROM mail_template WHERE template_key = r.template_key), TRUE) AS template_enabled \
        FROM report_run r JOIN report_schedule s ON s.period_type = r.period_type WHERE r.id = $1;", &[&report]).await.map_err(|e| e.to_string())?;
    let active: bool = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM users WHERE id = $1 AND role = 1 AND disabled_at IS NULL \
        AND deleted_at IS NULL AND NOT limit_login AND trim(email) = $2) AS active;",
            &[&user, &email],
        )
        .await
        .map_err(|e| e.to_string())?
        .get("active");
    let rendered: Option<Value> = report.get("rendered_mail");
    drop(client);
    let settings = get_mail_settings_from_database(pool)
        .await
        .map_err(|e| e.to_string())?;
    let kind: String = report.get("period_type");
    let selected: Vec<i32> = report.get("recipient_ids");
    let preference = if kind == "weekly" {
        settings.notification_prefs.report_weekly
    } else {
        settings.notification_prefs.report_monthly
    };
    let activation_valid = report
        .get::<_, Option<DateTime<Utc>>>("enabled_at")
        .is_some_and(|at| report.get::<_, DateTime<Utc>>("period_end") >= at);
    let permitted = active
        && report.get::<_, bool>("image_available")
        && report.get::<_, bool>("template_enabled")
        && rendered.is_some()
        && (!automatic
            || (report.get::<_, bool>("enabled")
                && activation_valid
                && preference
                && (selected.is_empty() || selected.contains(&user))));
    if !permitted {
        let client = pool.get().await.map_err(|e| e.to_string())?;
        client.execute("UPDATE report_delivery SET status = 'cancelled', last_error = '收件人、计划或模板已停用', claim_token = NULL, lease_until = NULL WHERE id = $1 AND claim_token = $2;", &[&id, &token]).await.map_err(|e| e.to_string())?;
        return Ok(true);
    }
    let result = match tokio::time::timeout(
        Duration::from_secs(90),
        mail_template::send_archived_report(
            pool,
            encryption_key,
            &email,
            rendered.unwrap_or(Value::Null),
            id,
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err("SMTP 投递超时".into()),
    };
    let client = pool.get().await.map_err(|e| e.to_string())?;
    match result {
        Ok(()) => {
            client.execute("UPDATE report_delivery SET status = 'sent', sent_at = NOW(), last_error = NULL, claim_token = NULL, lease_until = NULL WHERE id = $1 AND claim_token = $2;", &[&id, &token]).await.map_err(|e| e.to_string())?;
        }
        Err(error) => {
            client.execute("UPDATE report_delivery SET status = $3, available_at = NOW() + $4::BIGINT * INTERVAL '1 second', \
            last_error = $5, claim_token = NULL, lease_until = NULL WHERE id = $1 AND claim_token = $2;", &[&id, &token, &if attempts >= 5 { "failed" } else { "pending" }, &(60_i64 * i64::from(attempts.min(5))), &error]).await.map_err(|e| e.to_string())?;
        }
    }
    Ok(true)
}
