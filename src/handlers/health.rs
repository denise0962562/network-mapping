use actix_web::{HttpRequest, HttpResponse, Responder, get, web};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio_postgres::types::ToSql;

use crate::admin::UserBaseI;
use crate::logs::write::error_logs_error;

#[get("/api/config/monitor/operations")]
pub(crate) async fn monitor_operations(
    pool: web::Data<Pool>,
    settings: web::Data<crate::runtime_config::RuntimeSettings>,
    user: UserBaseI,
) -> impl Responder {
    if !is_admin(&user) {
        return HttpResponse::Forbidden()
            .json(json!({"success": false, "message": "仅管理员可以读取操作目录"}));
    }
    use crate::monitor::rules::{MonitorService, OperationDescriptor, static_catalogue};
    let mut operations = static_catalogue();
    let current = settings.monitor.get().await;
    let mut query_ids = std::collections::BTreeSet::new();
    let mut postgresql_available = false;
    if let Ok(client) = pool.get().await {
        // Match the monitor's bounded sample: high total cost and high peak cost.
        if let Ok(rows) = client.query("SELECT DISTINCT queryid FROM ( \
            (SELECT queryid FROM pg_stat_statements WHERE calls > 0 ORDER BY total_exec_time DESC LIMIT 500) \
            UNION (SELECT queryid FROM pg_stat_statements WHERE calls > 0 ORDER BY max_exec_time DESC LIMIT 500) \
            ) sampled WHERE queryid IS NOT NULL;", &[]).await {
            postgresql_available = true;
            query_ids.extend(rows.iter().map(|row| row.get::<_, i64>(0).to_string()));
        }
        // Query IDs may disappear after pg_stat_statements is reset. Keep IDs
        // used in restorable history selectable without exposing SQL text.
        if let Ok(rows) = client.query("SELECT document FROM runtime_configuration_revision WHERE namespace = 'monitor' ORDER BY revision DESC LIMIT 30;", &[]).await {
            for row in rows {
                if let Ok(document) = serde_json::from_value::<crate::config::MonitorConfig>(row.get("document")) {
                    query_ids.extend(document.operation_rules.into_iter().filter(|item| item.service == MonitorService::Postgresql && crate::monitor::rules::valid_operation(item.service, &item.operation)).map(|item| item.operation));
                }
            }
        }
    }
    query_ids.extend(
        current
            .value
            .operation_rules
            .iter()
            .filter(|item| item.service == MonitorService::Postgresql)
            .map(|item| item.operation.clone()),
    );
    operations.extend(query_ids.into_iter().map(|operation| OperationDescriptor {
        service: MonitorService::Postgresql,
        label: format!("SQL 查询 #{operation}"),
        operation,
        description: "按 pg_stat_statements 查询标识匹配，以采样窗口内的平均执行耗时判定；不是单次查询耗时。".into(),
    }));
    let defaults = MonitorService::ALL
        .into_iter()
        .map(|service| (service, current.value.default_rule(service)))
        .collect::<std::collections::BTreeMap<_, _>>();
    HttpResponse::Ok().json(json!({"success": true, "data": {
        "operations": operations, "defaults": defaults,
        "postgresql_available": postgresql_available,
        "postgresql_message": if postgresql_available { "" } else { "SQL 操作目录暂不可用：请检查 pg_stat_statements 扩展及读取权限。已保存的查询规则仍会显示。" }
    }}))
}

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

fn health_filter(query: &HealthAlertQuery) -> (String, Vec<&(dyn ToSql + Sync)>) {
    let mut conditions = Vec::new();
    let mut params: Vec<&(dyn ToSql + Sync)> = Vec::new();
    if let Some(value) = query.alert_type.as_ref() {
        params.push(value);
        conditions.push(format!("alert_type = ${}", params.len()));
    }
    if let Some(value) = query.severity.as_ref() {
        params.push(value);
        conditions.push(format!("severity = ${}", params.len()));
    }
    if let Some(value) = query.start.as_ref() {
        params.push(value);
        conditions.push(format!("occurred_at >= ${}", params.len()));
    }
    if let Some(value) = query.end.as_ref() {
        params.push(value);
        conditions.push(format!("occurred_at <= ${}", params.len()));
    }
    let sql = if conditions.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", conditions.join(" AND "))
    };
    (sql, params)
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
            error_logs_error(
                &req,
                "HealthAlertPoolError",
                "database_operation",
                &error_value,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };

    let (filter_sql, params) = health_filter(&query);

    let count_sql = format!("SELECT COUNT(*) FROM health_alert{filter_sql}");
    let total: i64 = match client.query_one(&count_sql, &params).await {
        Ok(row) => row.get(0),
        Err(error_value) => {
            error_logs_error(
                &req,
                "HealthAlertQueryError",
                "database_operation",
                &error_value,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };

    let list_sql = format!(
        "SELECT id, alert_type, alert_key, severity, summary, detail, occurred_at \
         FROM health_alert{filter_sql} ORDER BY occurred_at DESC, id DESC \
         LIMIT ${} OFFSET ${}",
        params.len() + 1,
        params.len() + 2,
    );
    let mut list_params = params;
    list_params.push(&page_size);
    list_params.push(&offset);
    let rows = match client.query(&list_sql, &list_params).await {
        Ok(rows) => rows,
        Err(error_value) => {
            error_logs_error(
                &req,
                "HealthAlertQueryError",
                "database_operation",
                &error_value,
            );
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

#[cfg(test)]
mod tests {
    use super::{HealthAlertQuery, health_filter};
    use chrono::{TimeZone, Utc};

    fn query() -> HealthAlertQuery {
        HealthAlertQuery {
            alert_type: None,
            severity: None,
            start: None,
            end: None,
            page: None,
            page_size: None,
        }
    }

    #[test]
    fn health_filter_omits_absent_predicates() {
        let value = query();
        let (sql, params) = health_filter(&value);
        assert!(sql.is_empty());
        assert!(params.is_empty());
    }

    #[test]
    fn health_filter_numbers_only_present_parameters() {
        let mut value = query();
        value.severity = Some("critical".to_owned());
        value.end = Some(Utc.timestamp_opt(1_700_000_000, 0).unwrap());
        let (sql, params) = health_filter(&value);
        assert_eq!(sql, " WHERE severity = $1 AND occurred_at <= $2");
        assert_eq!(params.len(), 2);
    }

    #[test]
    fn health_history_schema_has_an_ordering_index() {
        let sql = include_str!("../../source/database/init.sql");
        assert!(sql.contains("idx_health_alert_time"));
        assert!(sql.contains("health_alert (occurred_at DESC, id DESC)"));
    }
}
