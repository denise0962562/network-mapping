//! Transactional tag projection notifications for Elasticsearch.
use deadpool_postgres::GenericClient;
use serde_json::json;

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
