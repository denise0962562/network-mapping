use deadpool_postgres::{GenericClient, Pool};
use serde_json::json;

use crate::cli_progress::{NoopProgressReporter, ProgressReporter, ProgressUpdate};
use crate::search_content::extract_search_content;

const PROJECTION_COLUMNS: &str = r#"
    scope_type, scope_id, ip_address, port, protocol, service, banner, title,
    http_body, http_body_truncated, tls_subject, source, scanner_name,
    first_seen_at, last_seen_at, asn, isp, as_org, country_code, country_name,
    region_name, city_name, latest_endpoint_observation_id,
    latest_service_observation_id
"#;

fn projection_upsert_sql(filter: &str) -> String {
    let filter = if filter.is_empty() {
        "WHERE TRUE"
    } else {
        filter
    };
    format!(
        r#"
        INSERT INTO asset_endpoint_current ({PROJECTION_COLUMNS}, projection_version, updated_at)
        SELECT {PROJECTION_COLUMNS}, nextval('asset_endpoint_projection_version_seq'), NOW()
        FROM asset_endpoint_search_source source
        {filter}
        ON CONFLICT (scope_type, scope_id, ip_address, port) DO UPDATE SET
            protocol = EXCLUDED.protocol,
            service = EXCLUDED.service,
            banner = EXCLUDED.banner,
            title = EXCLUDED.title,
            http_body = EXCLUDED.http_body,
            http_body_truncated = EXCLUDED.http_body_truncated,
            tls_subject = EXCLUDED.tls_subject,
            source = EXCLUDED.source,
            scanner_name = EXCLUDED.scanner_name,
            first_seen_at = EXCLUDED.first_seen_at,
            last_seen_at = EXCLUDED.last_seen_at,
            asn = EXCLUDED.asn,
            isp = EXCLUDED.isp,
            as_org = EXCLUDED.as_org,
            country_code = EXCLUDED.country_code,
            country_name = EXCLUDED.country_name,
            region_name = EXCLUDED.region_name,
            city_name = EXCLUDED.city_name,
            latest_endpoint_observation_id = EXCLUDED.latest_endpoint_observation_id,
            latest_service_observation_id = EXCLUDED.latest_service_observation_id,
            projection_version = nextval('asset_endpoint_projection_version_seq'),
            updated_at = NOW()
        "#
    )
}

pub(crate) async fn refresh_for_execution<C>(
    client: &C,
    execution_id: i32,
) -> Result<u64, tokio_postgres::Error>
where
    C: GenericClient + Sync,
{
    // 完成事件通常远低于 observation 写入频率。串行化投影刷新可避免两个 execution
    // 并发完成时，较早快照覆盖较新 current 文档。
    client
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended('asset-endpoint-projection', 0));",
            &[],
        )
        .await?;
    let sql = projection_upsert_sql(
        "WHERE EXISTS (SELECT 1 FROM scan_observation affected \
         WHERE affected.execution_id = $1 \
           AND affected.ip_address = source.ip_address \
           AND affected.port = source.port)",
    );
    let updated = client.execute(&sql, &[&execution_id]).await?;
    client
        .execute(
            "INSERT INTO search_index_outbox (event_kind, aggregate_key, payload) \
             VALUES ('execution', $1::TEXT, JSONB_BUILD_OBJECT('execution_id', $1));",
            &[&execution_id],
        )
        .await?;
    Ok(updated)
}

pub(crate) async fn enqueue_ip<C>(client: &C, ip: &str) -> Result<(), tokio_postgres::Error>
where
    C: GenericClient + Sync,
{
    client
        .execute(
            "INSERT INTO search_index_outbox (event_kind, aggregate_key, payload) \
             VALUES ('ip', $1, $2);",
            &[&ip, &json!({"ip": ip})],
        )
        .await?;
    Ok(())
}

pub(crate) async fn enqueue_tag_assignments<C>(
    client: &C,
    tag_id: i64,
) -> Result<u64, tokio_postgres::Error>
where
    C: GenericClient + Sync,
{
    client
        .execute(
            "INSERT INTO search_index_outbox (event_kind, aggregate_key, payload) \
             SELECT 'ip', host(assignment.ip_address), \
                    JSONB_BUILD_OBJECT('ip', host(assignment.ip_address)) \
             FROM asset_ip_tag assignment WHERE assignment.tag_id = $1;",
            &[&tag_id],
        )
        .await
}

pub async fn ensure_initialized(
    pool: &Pool,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    backfill_search_content(pool, &NoopProgressReporter).await?;
    let mut connection = pool.get().await?;
    let transaction = connection.transaction().await?;
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended('asset-endpoint-projection', 0));",
            &[],
        )
        .await?;
    let initialized: bool = transaction
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM search_projection_state \
             WHERE state_key = 'postgres_projection_initialized') AS initialized;",
            &[],
        )
        .await?
        .get("initialized");
    if initialized {
        transaction.commit().await?;
        return Ok(false);
    }
    rebuild_in_transaction(&transaction).await?;
    transaction.commit().await?;
    Ok(true)
}

pub async fn rebuild(pool: &Pool) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    rebuild_with_progress(pool, &NoopProgressReporter).await
}

pub async fn rebuild_with_progress(
    pool: &Pool,
    reporter: &dyn ProgressReporter,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    backfill_search_content(pool, reporter).await?;
    reporter.report(ProgressUpdate::phase(
        "正在执行 PostgreSQL 当前端点投影重建",
    ));
    let mut connection = pool.get().await?;
    let transaction = connection.transaction().await?;
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended('asset-endpoint-projection', 0));",
            &[],
        )
        .await?;
    let count = rebuild_in_transaction(&transaction).await?;
    transaction.commit().await?;
    Ok(count)
}

async fn backfill_search_content(
    pool: &Pool,
    reporter: &dyn ProgressReporter,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let expected_total = if reporter.is_enabled() {
        reporter.report(ProgressUpdate::phase("正在统计待提取搜索内容的观察记录"));
        let total: i64 = pool
            .get()
            .await?
            .query_one(
                "SELECT COUNT(*)::BIGINT AS total FROM scan_observation \
                 WHERE NOT search_content_extracted;",
                &[],
            )
            .await?
            .get("total");
        Some(u64::try_from(total)?)
    } else {
        None
    };
    let mut completed = 0_u64;
    reporter.report(ProgressUpdate::count(
        "回填搜索内容",
        0,
        expected_total,
        "条",
        "",
    ));
    loop {
        let mut connection = pool.get().await?;
        let transaction = connection.transaction().await?;
        let rows = transaction
            .query(
                "SELECT id, data FROM scan_observation \
                 WHERE NOT search_content_extracted ORDER BY id \
                 FOR UPDATE SKIP LOCKED LIMIT 500;",
                &[],
            )
            .await?;
        if rows.is_empty() {
            transaction.commit().await?;
            break;
        }
        for row in &rows {
            let id: i64 = row.get("id");
            let data: Option<serde_json::Value> = row.get("data");
            let content = extract_search_content(data.as_ref());
            transaction
                .execute(
                    "UPDATE scan_observation SET title = $2, http_body = $3, \
                     http_body_truncated = $4, tls_subject = $5, search_content_extracted = TRUE \
                     WHERE id = $1;",
                    &[
                        &id,
                        &content.title,
                        &content.http_body,
                        &content.http_body_truncated,
                        &content.tls_subject,
                    ],
                )
                .await?;
        }
        completed = completed.saturating_add(rows.len() as u64);
        transaction.commit().await?;
        reporter.report(ProgressUpdate::count(
            "回填搜索内容",
            completed,
            expected_total,
            "条",
            "",
        ));
    }
    Ok(completed)
}

async fn rebuild_in_transaction<C>(client: &C) -> Result<u64, tokio_postgres::Error>
where
    C: GenericClient + Sync,
{
    client
        .execute("DELETE FROM asset_endpoint_current;", &[])
        .await?;
    let inserted = client.execute(&projection_upsert_sql(""), &[]).await?;
    client
        .execute(
            "INSERT INTO search_projection_state (state_key, state_value, updated_at) \
             VALUES ('postgres_projection_initialized', 'true', NOW()) \
             ON CONFLICT (state_key) DO UPDATE SET state_value = EXCLUDED.state_value, updated_at = NOW();",
            &[],
        )
        .await?;
    client
        .execute(
            "DELETE FROM search_index_outbox WHERE event_kind = 'full' AND processed_at IS NULL;",
            &[],
        )
        .await?;
    client
        .execute(
            "DELETE FROM search_projection_state WHERE state_key = 'elasticsearch_full_sync_index';",
            &[],
        )
        .await?;
    client
        .execute(
            "INSERT INTO search_index_outbox (event_kind, aggregate_key, payload) \
             VALUES ('full', 'all', '{}');",
            &[],
        )
        .await?;
    Ok(inserted)
}
