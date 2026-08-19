use actix_web::{HttpRequest, HttpResponse, Responder, get, web};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio_postgres::types::ToSql;

use crate::admin::UserBaseI;
use crate::logs::write::error_logs;

/// 健康告警查询过滤。`$1` 告警类型、`$2` 级别、`$3`/`$4` 时间范围，均为可空。
const FILTER_SQL: &str = "
    WHERE ($1::TEXT IS NULL OR alert_type = $1)
      AND ($2::TEXT IS NULL OR severity = $2)
      AND ($3::TIMESTAMPTZ IS NULL OR occurred_at >= $3)
      AND ($4::TIMESTAMPTZ IS NULL OR occurred_at <= $4)";

#[derive(Deserialize)]
pub struct HealthAlertQuery {
    alert_type: Option<String>,
    severity: Option<String>,
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
    page: Option<i64>,
    page_size: Option<i64>,
}

fn is_admin(user: &UserBaseI) -> bool {
    user.role == 1
}

fn pagination(page: Option<i64>, page_size: Option<i64>) -> (i64, i64) {
    (
        page.unwrap_or(1).max(1),
        page_size.unwrap_or(25).clamp(1, 100),
    )
}

#[get("/api/health/alerts")]
pub(crate) async fn list_health_alerts(
    req: HttpRequest,
    pool: web::Data<Pool>,
    query: web::Query<HealthAlertQuery>,
    user: UserBaseI,
) -> impl Responder {
    if !is_admin(&user) {
        return HttpResponse::Forbidden().json(json!({"success": false, "message": "forbidden"}));
    }

    let (page, page_size) = pagination(query.page, query.page_size);
    let offset = (page - 1) * page_size;

    let client = match pool.get().await {
        Ok(client) => client,
        Err(error_value) => {
            error_logs(&req, "HealthAlertPoolError", &error_value.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };

    let params: Vec<&(dyn ToSql + Sync)> =
        vec![&query.alert_type, &query.severity, &query.start, &query.end];

    let count_sql = format!("SELECT COUNT(*) FROM health_alert {FILTER_SQL}");
    let total: i64 = match client.query_one(&count_sql, &params).await {
        Ok(row) => row.get(0),
        Err(error_value) => {
            error_logs(&req, "HealthAlertQueryError", &error_value.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };

    let list_sql = format!(
        "SELECT id, alert_type, alert_key, severity, summary, detail, occurred_at \
         FROM health_alert {FILTER_SQL} ORDER BY occurred_at DESC, id DESC LIMIT $5 OFFSET $6"
    );
    let mut list_params = params;
    list_params.push(&page_size);
    list_params.push(&offset);
    let rows = match client.query(&list_sql, &list_params).await {
        Ok(rows) => rows,
        Err(error_value) => {
            error_logs(&req, "HealthAlertQueryError", &error_value.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };

    let items: Vec<Value> = rows
        .into_iter()
        .map(|row| {
            json!({
                "id": row.get::<_, i64>("id"),
                "alert_type": row.get::<_, String>("alert_type"),
                "alert_key": row.get::<_, String>("alert_key"),
                "severity": row.get::<_, String>("severity"),
                "summary": row.get::<_, String>("summary"),
                "detail": row.get::<_, Value>("detail"),
                "occurred_at": row.get::<_, DateTime<Utc>>("occurred_at"),
            })
        })
        .collect();

    HttpResponse::Ok().json(json!({
        "success": true,
        "items": items,
        "pagination": {"page": page, "page_size": page_size, "total": total}
    }))
}
