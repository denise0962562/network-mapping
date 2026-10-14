use super::{
    ApiError, Principal, Result, auth, console, model,
    query::{self, Search},
    request_id, tasks,
};
use crate::elasticsearch::ElasticsearchService;
use actix_web::{HttpRequest, http::StatusCode, web};
use chrono::{DateTime, Utc};
use deadpool_postgres::{GenericClient, Pool};
use serde_json::{Value, json};
use uuid::Uuid;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn annotations(
    req: &HttpRequest,
    pool: &Pool,
    es: &ElasticsearchService,
    p: &Principal,
    e: &super::catalog::Endpoint,
    parts: &[&str],
    v: &Value,
    ip: &str,
) -> Result<Value> {
    let found = query::endpoints(
        pool,
        es,
        p,
        &Search::default(),
        vec![json!({"term":{"ip":ip}})],
    )
    .await?;
    if found["items"].as_array().is_none_or(|a| a.is_empty()) {
        return Err(ApiError::missing());
    }
    let mut c = pool.get().await?;
    if e.method == "GET" {
        let rows=c.query("SELECT key,value,updated_at FROM api_asset_annotation WHERE client_id=$1 AND ip_address=$2::TEXT::INET ORDER BY key LIMIT 100",&[&p.client_pk,&ip]).await?;
        return Ok(
            json!({"items":rows.iter().map(|r|json!({"key":r.get::<_,String>(0),"value":r.get::<_,String>(1),"updated_at":r.get::<_,DateTime<Utc>>(2)})).collect::<Vec<_>>()}),
        );
    }
    let key = parts[3];
    if key.is_empty()
        || key.len() > 64
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(ApiError::bad("注释键无效"));
    }
    let tx = c.transaction().await?;
    tasks::authorize(&tx, p).await?;
    if e.method == "PUT" {
        console::allowed_keys(v, &["value"])?;
        let value = console::text(v, "value", 2048)?;
        let count:i64=tx.query_one("SELECT COUNT(*) FROM api_asset_annotation WHERE client_id=$1 AND ip_address=$2::TEXT::INET",&[&p.client_pk,&ip]).await?.get(0);
        if count>=100&&tx.query_opt("SELECT key FROM api_asset_annotation WHERE client_id=$1 AND ip_address=$2::TEXT::INET AND key=$3",&[&p.client_pk,&ip,&key]).await?.is_none(){return Err(ApiError::bad("每个资产注释最多 100 项"));}
        tx.execute("INSERT INTO api_asset_annotation(client_id,ip_address,key,value) VALUES($1,$2::TEXT::INET,$3,$4) ON CONFLICT(client_id,ip_address,key) DO UPDATE SET value=EXCLUDED.value,updated_at=NOW()",&[&p.client_pk,&ip,&key,&value]).await?;
    } else {
        tx.execute("DELETE FROM api_asset_annotation WHERE client_id=$1 AND ip_address=$2::TEXT::INET AND key=$3",&[&p.client_pk,&ip,&key]).await?;
    }
    auth::audit(
        &tx,
        Some(p.client_pk),
        "application",
        &p.client_id.to_string(),
        if e.method == "PUT" {
            "annotation.write"
        } else {
            "annotation.delete"
        },
        Some(ip),
        Some(request_id(req)),
        &json!({"key":key}),
    )
    .await?;
    tx.commit().await?;
    Ok(json!({"success":true}))
}
pub(crate) async fn dispatch(
    req: &HttpRequest,
    pool: &Pool,
    _es: &ElasticsearchService,
    p: &Principal,
    e: &super::catalog::Endpoint,
    parts: &[&str],
    v: &Value,
) -> Result<Value> {
    match parts[0] {
        "exports" | "reports" => jobs(req, pool, p, e, parts, v).await,
        "saved-searches" => saved_searches(req, pool, p, e, parts, v).await,
        "events" => events(req, pool, p, v).await,
        "webhooks" | "webhook-deliveries" => webhooks(req, pool, p, e, parts, v).await,
        _ => Err(ApiError::missing()),
    }
}
pub(crate) async fn event<C: GenericClient + Sync>(
    tx: &C,
    client: i32,
    kind: &str,
    resource: &str,
    payload: &Value,
    dedup: &str,
) -> Result<()> {
    tx.execute("INSERT INTO api_event_outbox(event_id,client_id,event_type,resource_id,payload,dedup_key) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(dedup_key) DO NOTHING",&[&Uuid::now_v7(),&client,&kind,&resource,&payload,&dedup]).await?;
    Ok(())
}
async fn jobs(
    req: &HttpRequest,
    pool: &Pool,
    p: &Principal,
    e: &super::catalog::Endpoint,
    parts: &[&str],
    v: &Value,
) -> Result<Value> {
    let kind = if parts[0] == "exports" {
        "export"
    } else {
        "report"
    };
    let scope = if kind == "export" {
        "assets:read"
    } else {
        "analytics:read"
    };
    if !p.has(scope) {
        return Err(ApiError::forbidden());
    }
    let mut c = pool.get().await?;
    if parts.len() == 1 && e.method == "POST" {
        console::allowed_keys(
            v,
            if kind == "report" {
                &["format", "start_at", "end_at"]
            } else {
                &["query", "fields", "format", "start_at", "end_at"]
            },
        )?;
        if v.get("format").is_some_and(|v| !v.is_string()) {
            return Err(ApiError::bad("format 必须为字符串"));
        }
        let format = v["format"].as_str().unwrap_or("json");
        if !matches!(format, "json" | "jsonl" | "csv") {
            return Err(ApiError::bad("导出格式为 json、jsonl 或 csv"));
        }
        let search:Search=serde_json::from_value(json!({"query":v.get("query"),"fields":v.get("fields"),"start_at":v.get("start_at"),"end_at":v.get("end_at")})).map_err(|_|ApiError::bad("查询参数无效"))?;
        search.validate(p)?;
        query::compile(search.query.as_deref().unwrap_or(""), p)?;
        if kind == "report" {
            let start = search
                .start_at
                .ok_or_else(|| ApiError::bad("报告必须指定 start_at"))?;
            let end = search
                .end_at
                .ok_or_else(|| ApiError::bad("报告必须指定 end_at"))?;
            if end > Utc::now().timestamp_millis() || end - start > 366 * 86400000i64 {
                return Err(ApiError::bad("报告范围必须已结束，最多 366 天"));
            }
        }
        let key = tasks::idempotency_key(req)?;
        let tx = c.transaction().await?;
        tasks::authorize(&tx, p).await?;
        let op = format!("{kind}.create");
        if let Some(result) = tasks::replay(&tx, p, &op, &key, v).await? {
            tx.commit().await?;
            return Ok(result);
        }
        let running:i64=tx.query_one("SELECT COUNT(*) FROM api_job WHERE client_id=$1 AND status IN ('queued','running') AND expires_at>NOW()",&[&p.client_pk]).await?.get(0);
        if running >= 2 {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "job_concurrency_exceeded",
                "每个应用最多两个未完成导出/报告",
            ));
        }
        auth::consume(
            &tx,
            p.client_pk,
            &format!("{kind}.day"),
            p.policy.exports_per_day,
            1,
            true,
        )
        .await?;
        let id = Uuid::now_v7();
        tx.execute("INSERT INTO api_job(id,client_id,credential_id,policy_revision,kind,spec) VALUES($1,$2,$3,$4,$5,$6)",&[&id,&p.client_pk,&p.credential_id,&p.revision,&kind,&v]).await?;
        let result = json!({"id":id,"status":"queued","kind":kind});
        tasks::remember(&tx, p, &op, &key, v, &result).await?;
        auth::audit(
            &tx,
            Some(p.client_pk),
            "application",
            &p.client_id.to_string(),
            &op,
            Some(&id.to_string()),
            Some(request_id(req)),
            &json!({"format":format}),
        )
        .await?;
        tx.commit().await?;
        return Ok(result);
    }
    if parts.len() == 1 {
        let rows=c.query("SELECT id,kind,status,created_at,finished_at,expires_at,last_error,octet_length(artifact)::BIGINT AS bytes FROM api_job WHERE client_id=$1 AND kind=$2 ORDER BY created_at DESC LIMIT 100",&[&p.client_pk,&kind]).await?;
        return Ok(json!({"items":rows.iter().map(job_summary).collect::<Vec<_>>()}));
    }
    let id = model::parse_uuid(parts[1])?;
    let row=c.query_opt("SELECT *,octet_length(artifact)::BIGINT AS bytes FROM api_job WHERE id=$1 AND client_id=$2 AND kind=$3",&[&id,&p.client_pk,&kind]).await?.ok_or_else(ApiError::missing)?;
    if e.method == "GET" && row.get::<_, i64>("policy_revision") != p.revision {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "artifact_policy_changed",
            "授权已变更，请在当前授权下重新生成文件",
        ));
    }
    if e.method == "GET" {
        if parts.len() == 2 {
            return Ok(job_summary(&row));
        }
        if row.get::<_, String>("status") != "succeeded"
            || row.get::<_, DateTime<Utc>>("expires_at") <= Utc::now()
        {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "artifact_unavailable",
                "任务未完成或文件已过期",
            ));
        }
        if parts[2] == "data" {
            return Ok(
                json!({"payload":row.get::<_, Option<Value>>("result").unwrap_or(Value::Null),"artifact_checksum":row.get::<_,Option<String>>("artifact_checksum")}),
            );
        }
        let spec: Value = row.get("spec");
        let format = if parts.len() > 3 {
            parts[3]
        } else {
            spec["format"].as_str().unwrap_or("json")
        };
        if !["json", "jsonl", "csv"].contains(&format) {
            return Err(ApiError::bad("文件格式无效"));
        }
        let bytes: Vec<u8> = if kind == "report" {
            super::worker::render_artifact(
                &row.get::<_, Option<Value>>("result").unwrap_or(Value::Null),
                format,
            )?
            .0
        } else {
            row.get::<_, Option<Vec<u8>>>("artifact")
                .ok_or_else(ApiError::missing)?
        };
        return Ok(
            json!({"_download":{"base64":openssl::base64::encode_block(&bytes),"filename":format!("{kind}-{id}.{format}"),"content_type":super::worker::content_type(format)}}),
        );
    }
    let tx = c.transaction().await?;
    tasks::authorize(&tx, p).await?;
    let status = if e.method == "DELETE" {
        "deleted"
    } else {
        "cancelled"
    };
    let changed=tx.execute("UPDATE api_job SET status=$3,artifact=NULL,result=NULL,claim_token=NULL,lease_expires_at=NULL,finished_at=COALESCE(finished_at,NOW()) WHERE id=$1 AND client_id=$2 AND ($3='deleted' OR status IN ('queued','running'))",&[&id,&p.client_pk,&status]).await?;
    if changed == 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "job_not_running",
            "生成任务已经结束，请刷新状态",
        ));
    }
    auth::audit(
        &tx,
        Some(p.client_pk),
        "application",
        &p.client_id.to_string(),
        &format!("{kind}.{status}"),
        Some(&id.to_string()),
        Some(request_id(req)),
        &json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(json!({"id":id,"status":status}))
}
fn job_summary(r: &tokio_postgres::Row) -> Value {
    json!({"id":r.get::<_,Uuid>("id"),"kind":r.get::<_,String>("kind"),"status":r.get::<_,String>("status"),"created_at":r.get::<_,DateTime<Utc>>("created_at"),"finished_at":r.get::<_,Option<DateTime<Utc>>>("finished_at"),"expires_at":r.get::<_,DateTime<Utc>>("expires_at"),"last_error":r.get::<_,Option<String>>("last_error"),"bytes":r.get::<_,Option<i64>>("bytes")})
}
async fn saved_searches(
    req: &HttpRequest,
    pool: &Pool,
    p: &Principal,
    e: &super::catalog::Endpoint,
    parts: &[&str],
    v: &Value,
) -> Result<Value> {
    let mut c = pool.get().await?;
    if e.method == "GET" {
        let id = parts.get(1).map(|s| model::parse_uuid(s)).transpose()?;
        let rows=c.query("SELECT id,document,revision,created_at,updated_at FROM api_saved_search WHERE client_id=$1 AND ($2::UUID IS NULL OR id=$2) ORDER BY updated_at DESC LIMIT 100",&[&p.client_pk,&id]).await?;
        if id.is_some() && rows.is_empty() {
            return Err(ApiError::missing());
        }
        return Ok(
            json!({"items":rows.iter().map(|r|json!({"id":r.get::<_,Uuid>("id"),"document":r.get::<_,Value>("document"),"revision":r.get::<_,i64>("revision"),"updated_at":r.get::<_,DateTime<Utc>>("updated_at")})).collect::<Vec<_>>()}),
        );
    }
    let tx = c.transaction().await?;
    tasks::authorize(&tx, p).await?;
    let id = parts
        .get(1)
        .map(|s| model::parse_uuid(s))
        .transpose()?
        .unwrap_or_else(Uuid::now_v7);
    if e.method == "DELETE" {
        if tx
            .execute(
                "DELETE FROM api_saved_search WHERE client_id=$1 AND id=$2",
                &[&p.client_pk, &id],
            )
            .await?
            == 0
        {
            return Err(ApiError::missing());
        }
    } else {
        console::allowed_keys(v, &["name", "query", "expected_revision"])?;
        console::text(v, "name", 100)?;
        let q = console::text(v, "query", 2048)?;
        query::compile(&q, p)?;
        let document = json!({"name":v["name"],"query":q});
        if e.method=="POST" {
            let count:i64=tx.query_one("SELECT COUNT(*) FROM api_saved_search WHERE client_id=$1",&[&p.client_pk]).await?.get(0);if count>=100{return Err(ApiError::bad("保存查询最多 100 项"));}
            tx.execute("INSERT INTO api_saved_search(id,client_id,document) VALUES($1,$2,$3)",&[&id,&p.client_pk,&document]).await?;
        }else if tx.execute("UPDATE api_saved_search SET document=$3,revision=revision+1,updated_at=NOW() WHERE client_id=$1 AND id=$2 AND revision=$4",&[&p.client_pk,&id,&document,&v["expected_revision"].as_i64().unwrap_or(-1)]).await?==0{return Err(ApiError::new(StatusCode::CONFLICT,"revision_conflict","查询不存在或已变更"));}
    }
    auth::audit(
        &tx,
        Some(p.client_pk),
        "application",
        &p.client_id.to_string(),
        "saved_search.change",
        Some(&id.to_string()),
        Some(request_id(req)),
        &json!({"method":e.method}),
    )
    .await?;
    tx.commit().await?;
    Ok(json!({"id":id}))
}
async fn events(req: &HttpRequest, pool: &Pool, p: &Principal, v: &Value) -> Result<Value> {
    let q = if req.method().as_str() == "GET" {
        web::Query::<std::collections::HashMap<String, String>>::from_query(req.query_string())
            .map_err(|_| ApiError::bad("查询参数无效"))?
            .into_inner()
    } else {
        console::allowed_keys(v, &["after", "page_size"])?;
        v.as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    v.as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| v.to_string()),
                )
            })
            .collect()
    };
    let after = q
        .get("after")
        .map(|s| s.parse::<i64>().map_err(|_| ApiError::bad("after 无效")))
        .transpose()?
        .unwrap_or(0);
    let size = q
        .get("page_size")
        .map(|s| {
            s.parse::<i64>()
                .map_err(|_| ApiError::bad("page_size 无效"))
        })
        .transpose()?
        .unwrap_or(50);
    if !(1..=100).contains(&size) {
        return Err(ApiError::bad("page_size 必须为 1–100"));
    }
    let rows = pool
        .get()
        .await?
        .query(
            "SELECT * FROM api_event_outbox WHERE client_id=$1 AND id>$2 ORDER BY id LIMIT $3",
            &[&p.client_pk, &after, &size],
        )
        .await?;
    let mut items = Vec::new();
    for row in &rows {
        let kind: String = row.get("event_type");
        let resource: String = row.get("resource_id");
        let payload: Value = row.get("payload");
        if super::worker::resource_allowed(pool, p, &kind, &resource, &payload).await? {
            items.push(json!({"id":row.get::<_,Uuid>("event_id"),"type":kind,"resource_id":resource,"payload":payload,"occurred_at":row.get::<_,DateTime<Utc>>("created_at"),"version":1}));
        }
    }
    Ok(
        json!({"items":items,"next_after":rows.last().map(|r|r.get::<_,i64>("id")).unwrap_or(after),"delivery_semantics":"at_least_once"}),
    )
}
pub(crate) fn event_allowed(p: &Principal, kind: &str) -> bool {
    p.has("events:read")
        && p.has(if kind.starts_with("task.") {
            "tasks:read"
        } else if kind == "asset.ready" {
            "assets:read"
        } else if kind.starts_with("export.") {
            "exports:read"
        } else if kind.starts_with("report.") {
            "reports:read"
        } else {
            "webhooks:manage"
        })
}
pub(crate) fn validate_webhook_url(url: &str, allowed: &[String]) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(url).map_err(|_| ApiError::bad("回调地址无效"))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port_or_known_default() != Some(443)
        || url
            .host_str()
            .is_none_or(|h| !allowed.iter().any(|a| a.eq_ignore_ascii_case(h)))
        || url.as_str().len() > 2048
    {
        return Err(ApiError::bad(
            "回调地址必须为平台批准域名的 HTTPS 443 地址，不允许凭据或片段",
        ));
    }
    Ok(url)
}
pub(crate) fn public_ip(ip: std::net::IpAddr) -> bool {
    match crate::client_ip::normalize_ip(ip) {
        std::net::IpAddr::V4(ip) => {
            let n = u32::from(ip);
            ![
                "0.0.0.0/8",
                "10.0.0.0/8",
                "100.64.0.0/10",
                "127.0.0.0/8",
                "169.254.0.0/16",
                "172.16.0.0/12",
                "192.0.0.0/24",
                "192.0.2.0/24",
                "192.88.99.0/24",
                "192.168.0.0/16",
                "198.18.0.0/15",
                "198.51.100.0/24",
                "203.0.113.0/24",
                "224.0.0.0/3",
            ]
            .iter()
            .any(|s| {
                s.parse::<ipnet::Ipv4Net>()
                    .expect("constant subnet")
                    .contains(&std::net::Ipv4Addr::from(n))
            })
        }
        std::net::IpAddr::V6(ip) => {
            "2000::/3"
                .parse::<ipnet::Ipv6Net>()
                .expect("constant subnet")
                .contains(&ip)
                && !["2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"]
                    .iter()
                    .any(|s| {
                        s.parse::<ipnet::Ipv6Net>()
                            .expect("constant subnet")
                            .contains(&ip)
                    })
        }
    }
}
pub(crate) async fn allowed_webhook_hosts(pool: &Pool) -> Result<Vec<String>> {
    let v: Value = pool
        .get()
        .await?
        .query_one("SELECT document FROM api_platform_settings", &[])
        .await?
        .get(0);
    serde_json::from_value(
        v.get("webhook_allowed_hosts")
            .cloned()
            .unwrap_or_else(|| json!([])),
    )
    .map_err(|_| ApiError::unavailable())
}
async fn webhooks(
    req: &HttpRequest,
    pool: &Pool,
    p: &Principal,
    e: &super::catalog::Endpoint,
    parts: &[&str],
    v: &Value,
) -> Result<Value> {
    let mut c = pool.get().await?;
    if parts[0] == "webhook-deliveries" || parts.last() == Some(&"deliveries") {
        let id = model::parse_uuid(parts[1])?;
        let single = parts[0] == "webhook-deliveries";
        if e.method == "POST" {
            let tx = c.transaction().await?;
            tasks::authorize(&tx, p).await?;
            if tx.execute("UPDATE api_webhook_delivery d SET status='pending',next_attempt_at=NOW(),attempt_count=0,claim_token=NULL,lease_expires_at=NULL FROM api_webhook w WHERE d.id=$1 AND d.webhook_id=w.id AND w.client_id=$2 AND w.enabled AND w.deleted_at IS NULL AND d.status='failed'",&[&id,&p.client_pk]).await?==0{return Err(ApiError::new(StatusCode::CONFLICT,"delivery_not_retryable","投递不存在或不可重试"));}
            auth::audit(
                &tx,
                Some(p.client_pk),
                "application",
                &p.client_id.to_string(),
                "webhook.retry",
                Some(&id.to_string()),
                Some(request_id(req)),
                &json!({}),
            )
            .await?;
            tx.commit().await?;
            return Ok(json!({"id":id,"status":"pending"}));
        }
        let rows=c.query("SELECT d.* FROM api_webhook_delivery d JOIN api_webhook w ON w.id=d.webhook_id WHERE w.client_id=$1 AND (($2 AND d.id=$3) OR (NOT $2 AND w.id=$3)) ORDER BY d.created_at DESC LIMIT 100",&[&p.client_pk,&single,&id]).await?;
        if single && rows.is_empty() {
            return Err(ApiError::missing());
        }
        return Ok(
            json!({"items":rows.iter().map(|r|json!({"id":r.get::<_,Uuid>("id"),"status":r.get::<_,String>("status"),"attempt_count":r.get::<_,i32>("attempt_count"),"response_status":r.get::<_,Option<i32>>("response_status"),"last_error":r.get::<_,Option<String>>("last_error"),"created_at":r.get::<_,DateTime<Utc>>("created_at")})).collect::<Vec<_>>()}),
        );
    }
    if e.method == "GET" {
        let id = parts.get(1).map(|s| model::parse_uuid(s)).transpose()?;
        let rows=c.query("SELECT id,url,event_types,enabled,created_at FROM api_webhook WHERE client_id=$1 AND deleted_at IS NULL AND ($2::UUID IS NULL OR id=$2) ORDER BY created_at DESC LIMIT 100",&[&p.client_pk,&id]).await?;
        if id.is_some() && rows.is_empty() {
            return Err(ApiError::missing());
        }
        return Ok(
            json!({"items":rows.iter().map(|r|json!({"id":r.get::<_,Uuid>(0),"url":r.get::<_,String>(1),"event_types":r.get::<_,Vec<String>>(2),"enabled":r.get::<_,bool>(3),"created_at":r.get::<_,DateTime<Utc>>(4)})).collect::<Vec<_>>()}),
        );
    }
    let id = parts
        .get(1)
        .map(|s| model::parse_uuid(s))
        .transpose()?
        .unwrap_or_else(Uuid::now_v7);
    if e.path.ends_with("/test") {
        let tx = c.transaction().await?;
        tasks::authorize(&tx, p).await?;
        tx.query_opt("SELECT id FROM api_webhook WHERE id=$1 AND client_id=$2 AND enabled AND deleted_at IS NULL",&[&id,&p.client_pk]).await?.ok_or_else(ApiError::missing)?;
        let event_id = Uuid::now_v7();
        event(
            &tx,
            p.client_pk,
            "webhook.test",
            &id.to_string(),
            &json!({"test":true,"subscription_id":id}),
            &event_id.to_string(),
        )
        .await?;
        tx.execute("INSERT INTO api_webhook_delivery(id,webhook_id,event_id) SELECT $1,$2,id FROM api_event_outbox WHERE dedup_key=$3",&[&Uuid::now_v7(),&id,&event_id.to_string()]).await?;
        tx.commit().await?;
        return Ok(json!({"event_id":event_id,"status":"pending"}));
    }
    let mut secret = None;
    let mutation = if e.method == "DELETE" {
        None
    } else {
        console::allowed_keys(v, &["url", "event_types", "enabled"])?;
        let url = console::text(v, "url", 2048)?;
        validate_webhook_url(&url, &allowed_webhook_hosts(pool).await?)?;
        let types: Vec<String> = serde_json::from_value(v["event_types"].clone())
            .map_err(|_| ApiError::bad("事件类型列表无效"))?;
        if types.is_empty()
            || types.len() > model::EVENT_TYPES.len()
            || types
                .iter()
                .any(|s| !model::EVENT_TYPES.contains(&s.as_str()) || !event_allowed(p, s))
        {
            return Err(ApiError::forbidden());
        }
        let enabled = v
            .get("enabled")
            .map(|v| {
                v.as_bool()
                    .ok_or_else(|| ApiError::bad("enabled 必须为布尔值"))
            })
            .transpose()?
            .unwrap_or(true);
        Some((url, types, enabled))
    };
    let tx = c.transaction().await?;
    tasks::authorize(&tx, p).await?;
    if let Some((url,types,enabled))=mutation {
        if e.method=="POST" {
            let count:i64=tx.query_one("SELECT COUNT(*) FROM api_webhook WHERE client_id=$1 AND deleted_at IS NULL",&[&p.client_pk]).await?.get(0);if count>=p.policy.max_webhooks{return Err(ApiError::bad("订阅数量超过上限"));}
            let token=auth::generate_key(Uuid::new_v4())?;let config=req.app_data::<web::Data<crate::config::ServerConfig>>().ok_or_else(ApiError::unavailable)?;
            let (nonce,tag,ciphertext)=crate::identity::encrypt_data(token.as_bytes(),config.encrypt_key.as_bytes()).map_err(|_|ApiError::unavailable())?;
            let encrypted=[nonce,tag,ciphertext].concat();
            tx.execute("INSERT INTO api_webhook(id,client_id,credential_id,url,event_types,enabled,signing_secret) VALUES($1,$2,$3,$4,$5,$6,$7)",&[&id,&p.client_pk,&p.credential_id,&url,&types,&enabled,&encrypted]).await?;secret=Some(token);
        }else if tx.execute("UPDATE api_webhook SET url=$3,event_types=$4,enabled=$5 WHERE id=$1 AND client_id=$2 AND deleted_at IS NULL",&[&id,&p.client_pk,&url,&types,&enabled]).await?==0{return Err(ApiError::missing());}
    }else if tx.execute("UPDATE api_webhook SET enabled=FALSE,deleted_at=NOW() WHERE id=$1 AND client_id=$2 AND deleted_at IS NULL",&[&id,&p.client_pk]).await?==0{return Err(ApiError::missing());}
    auth::audit(
        &tx,
        Some(p.client_pk),
        "application",
        &p.client_id.to_string(),
        "webhook.change",
        Some(&id.to_string()),
        Some(request_id(req)),
        &json!({"method":e.method}),
    )
    .await?;
    tx.commit().await?;
    Ok(json!({"id":id,"signing_secret":secret,"display_once":secret.is_some()}))
}
