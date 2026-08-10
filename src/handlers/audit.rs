use actix_web::{HttpRequest, HttpResponse, Responder, get, web};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::admin::UserBaseI;
use crate::audit::{AuditContext, AuditEvent, write_standalone};
use crate::logs::write::error_logs;

#[derive(Deserialize)]
pub struct AuditQuery {
    category: Option<String>,
    action: Option<String>,
    outcome: Option<String>,
    actor_id: Option<String>,
    resource_type: Option<String>,
    resource_id: Option<String>,
    keyword: Option<String>,
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
    page: Option<i64>,
    page_size: Option<i64>,
}

#[derive(Serialize)]
struct AuditEventResponse {
    event_id: Uuid,
    occurred_at: DateTime<Utc>,
    category: String,
    action: String,
    outcome: String,
    severity: String,
    actor_type: String,
    actor_id: Option<String>,
    actor_name: Option<String>,
    resource_type: Option<String>,
    resource_id: Option<String>,
    request_id: Option<Uuid>,
    source_ip: Option<String>,
    user_agent: Option<String>,
    http_method: Option<String>,
    request_path: Option<String>,
    response_status: Option<i16>,
    reason_code: Option<String>,
    changes: Option<Value>,
    metadata: Value,
}

fn event_from_row(row: tokio_postgres::Row) -> AuditEventResponse {
    AuditEventResponse {
        event_id: row.get("event_id"),
        occurred_at: row.get("occurred_at"),
        category: row.get("category"),
        action: row.get("action"),
        outcome: row.get("outcome"),
        severity: row.get("severity"),
        actor_type: row.get("actor_type"),
        actor_id: row.get("actor_id"),
        actor_name: row.get("actor_name"),
        resource_type: row.get("resource_type"),
        resource_id: row.get("resource_id"),
        request_id: row.get("request_id"),
        source_ip: row.get("source_ip"),
        user_agent: row.get("user_agent"),
        http_method: row.get("http_method"),
        request_path: row.get("request_path"),
        response_status: row.get("response_status"),
        reason_code: row.get("reason_code"),
        changes: row.get("changes"),
        metadata: row.get("metadata"),
    }
}

const FILTER_SQL: &str = "
    WHERE ($1::TEXT IS NULL OR category = $1)
      AND ($2::TEXT IS NULL OR action = $2)
      AND ($3::TEXT IS NULL OR outcome = $3)
      AND ($4::TEXT IS NULL OR actor_id = $4)
      AND ($5::TEXT IS NULL OR resource_type = $5)
      AND ($6::TEXT IS NULL OR resource_id = $6)
      AND ($7::TIMESTAMPTZ IS NULL OR occurred_at >= $7)
      AND ($8::TIMESTAMPTZ IS NULL OR occurred_at <= $8)
      AND ($9::TEXT IS NULL OR action ILIKE '%' || $9 || '%'
           OR COALESCE(actor_name, '') ILIKE '%' || $9 || '%'
           OR COALESCE(resource_id, '') ILIKE '%' || $9 || '%')";

fn is_admin(user: &UserBaseI) -> bool {
    user.role == 1
}

fn pagination(page: Option<i64>, page_size: Option<i64>) -> (i64, i64) {
    (
        page.unwrap_or(1).max(1),
        page_size.unwrap_or(25).clamp(1, 100),
    )
}

#[get("/api/audit/events")]
pub(crate) async fn list_audit_events(
    req: HttpRequest,
    pool: web::Data<Pool>,
    query: web::Query<AuditQuery>,
    user: UserBaseI,
) -> impl Responder {
    if !is_admin(&user) {
        let mut event = AuditEvent::user("authorization", "audit.query", "denied", &user);
        event.response_status = Some(403);
        event.reason_code = Some("administrator_required".to_owned());
        write_standalone(pool.get_ref(), &AuditContext::from_request(&req), &event).await;
        return HttpResponse::Forbidden().json(json!({"success": false, "message": "forbidden"}));
    }

    let (page, page_size) = pagination(query.page, query.page_size);
    let offset = (page - 1) * page_size;
    let client = match pool.get().await {
        Ok(client) => client,
        Err(error_value) => {
            error_logs(&req, "AuditQueryPoolError", &error_value.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let filter_params: &[&(dyn tokio_postgres::types::ToSql + Sync)] = &[
        &query.category,
        &query.action,
        &query.outcome,
        &query.actor_id,
        &query.resource_type,
        &query.resource_id,
        &query.start,
        &query.end,
        &query.keyword,
    ];
    let count_sql = format!("SELECT COUNT(*) FROM audit_event {FILTER_SQL}");
    let total: i64 = match client.query_one(&count_sql, filter_params).await {
        Ok(row) => row.get(0),
        Err(error_value) => {
            error_logs(&req, "AuditQueryError", &error_value.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let list_sql = format!(
        "SELECT event_id, occurred_at, category, action, outcome, severity, actor_type, actor_id, \
         actor_name, resource_type, resource_id, request_id, source_ip::TEXT AS source_ip, user_agent, \
         http_method, request_path, response_status, reason_code, changes, metadata \
         FROM audit_event {FILTER_SQL} ORDER BY occurred_at DESC, id DESC LIMIT $10 OFFSET $11"
    );
    let mut params = filter_params.to_vec();
    params.push(&page_size);
    params.push(&offset);
    let rows = match client.query(&list_sql, &params).await {
        Ok(rows) => rows,
        Err(error_value) => {
            error_logs(&req, "AuditQueryError", &error_value.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let items: Vec<AuditEventResponse> = rows.into_iter().map(event_from_row).collect();

    let mut event = AuditEvent::user("audit", "audit.query", "success", &user);
    event.response_status = Some(200);
    event.metadata = json!({"result_count": items.len()});
    if let Err(error_value) =
        crate::audit::write(&client, &AuditContext::from_request(&req), &event).await
    {
        error_logs(&req, "AuditQueryAuditError", &error_value.to_string());
    }

    HttpResponse::Ok().json(json!({
        "success": true,
        "items": items,
        "pagination": {"page": page, "page_size": page_size, "total": total}
    }))
}

#[get("/api/audit/events/{event_id}")]
pub(crate) async fn get_audit_event(
    req: HttpRequest,
    pool: web::Data<Pool>,
    event_id: web::Path<Uuid>,
    user: UserBaseI,
) -> impl Responder {
    if !is_admin(&user) {
        return HttpResponse::Forbidden().finish();
    }
    let client = match pool.get().await {
        Ok(client) => client,
        Err(error_value) => {
            error_logs(&req, "AuditDetailPoolError", &error_value.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let row = match client
        .query_opt(
            "SELECT event_id, occurred_at, category, action, outcome, severity, actor_type, actor_id, \
             actor_name, resource_type, resource_id, request_id, source_ip::TEXT AS source_ip, user_agent, \
             http_method, request_path, response_status, reason_code, changes, metadata \
             FROM audit_event WHERE event_id = $1",
            &[&event_id.into_inner()],
        )
        .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return HttpResponse::NotFound().finish(),
        Err(error_value) => {
            error_logs(&req, "AuditDetailError", &error_value.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    HttpResponse::Ok().json(json!({"success": true, "data": event_from_row(row)}))
}

fn csv_cell(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

#[get("/api/audit/export")]
pub(crate) async fn export_audit_events(
    req: HttpRequest,
    pool: web::Data<Pool>,
    query: web::Query<AuditQuery>,
    user: UserBaseI,
) -> impl Responder {
    if !is_admin(&user) {
        return HttpResponse::Forbidden().finish();
    }
    let client = match pool.get().await {
        Ok(client) => client,
        Err(error_value) => {
            error_logs(&req, "AuditExportPoolError", &error_value.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let params: &[&(dyn tokio_postgres::types::ToSql + Sync)] = &[
        &query.category,
        &query.action,
        &query.outcome,
        &query.actor_id,
        &query.resource_type,
        &query.resource_id,
        &query.start,
        &query.end,
        &query.keyword,
    ];
    let sql = format!(
        "SELECT event_id, occurred_at, category, action, outcome, actor_type, actor_id, actor_name, \
         resource_type, resource_id, request_id, source_ip::TEXT AS source_ip, reason_code \
         FROM audit_event {FILTER_SQL} ORDER BY occurred_at DESC, id DESC LIMIT 10000"
    );
    let rows = match client.query(&sql, params).await {
        Ok(rows) => rows,
        Err(error_value) => {
            error_logs(&req, "AuditExportError", &error_value.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let mut csv = String::from(
        "event_id,occurred_at,category,action,outcome,actor_type,actor_id,actor_name,resource_type,resource_id,request_id,source_ip,reason_code\n",
    );
    for row in &rows {
        let values = [
            row.get::<_, Uuid>("event_id").to_string(),
            row.get::<_, DateTime<Utc>>("occurred_at").to_rfc3339(),
            row.get::<_, String>("category"),
            row.get::<_, String>("action"),
            row.get::<_, String>("outcome"),
            row.get::<_, String>("actor_type"),
            row.get::<_, Option<String>>("actor_id").unwrap_or_default(),
            row.get::<_, Option<String>>("actor_name")
                .unwrap_or_default(),
            row.get::<_, Option<String>>("resource_type")
                .unwrap_or_default(),
            row.get::<_, Option<String>>("resource_id")
                .unwrap_or_default(),
            row.get::<_, Option<Uuid>>("request_id")
                .map(|value| value.to_string())
                .unwrap_or_default(),
            row.get::<_, Option<String>>("source_ip")
                .unwrap_or_default(),
            row.get::<_, Option<String>>("reason_code")
                .unwrap_or_default(),
        ];
        csv.push_str(
            &values
                .iter()
                .map(|value| csv_cell(value))
                .collect::<Vec<_>>()
                .join(","),
        );
        csv.push('\n');
    }
    let mut event = AuditEvent::user("audit", "audit.export", "success", &user);
    event.response_status = Some(200);
    event.metadata = json!({"exported_count": rows.len(), "limit": 10000});
    if let Err(error_value) =
        crate::audit::write(&client, &AuditContext::from_request(&req), &event).await
    {
        error_logs(&req, "AuditExportAuditError", &error_value.to_string());
    }
    HttpResponse::Ok()
        .insert_header(("Content-Type", "text/csv; charset=utf-8"))
        .insert_header((
            "Content-Disposition",
            "attachment; filename=network-mapping-audit.csv",
        ))
        .body(csv)
}

#[cfg(test)]
mod tests {
    use super::{csv_cell, pagination};

    #[test]
    fn pagination_bounds_are_stable() {
        assert_eq!(pagination(Some(-1), Some(500)), (1, 100));
        assert_eq!(pagination(None, None), (1, 25));
    }

    #[test]
    fn csv_cells_escape_quotes() {
        assert_eq!(csv_cell("a\"b"), "\"a\"\"b\"");
    }
}
