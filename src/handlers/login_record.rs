use std::net::IpAddr;

use actix_web::{HttpRequest, HttpResponse, Responder, get, web};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::error;
use uuid::Uuid;

use crate::admin::UserBaseI;
use crate::audit::{AuditContext, AuditEvent, write as write_audit, write_standalone};
use crate::get_unix_epoch_ms;

const DEFAULT_PAGE_SIZE: u32 = 10;
const MAX_PAGE_SIZE: u32 = 50;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginRecordQuery {
    page: Option<u32>,
    page_size: Option<u32>,
    outcome: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginRecord {
    event_id: Uuid,
    occurred_at: DateTime<Utc>,
    outcome: String,
    source_ip: Option<String>,
    user_agent: Option<String>,
    reason_code: Option<String>,
    auth_method: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginRecordPagination {
    page: u32,
    page_size: u32,
    total: i64,
    total_pages: u32,
}

fn normalize_query(query: &LoginRecordQuery) -> Result<(u32, u32, Option<String>), &'static str> {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query
        .page_size
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .clamp(1, MAX_PAGE_SIZE);
    let outcome = query.outcome.as_deref().filter(|value| !value.is_empty());
    if !matches!(outcome, None | Some("success" | "failure")) {
        return Err("登录结果筛选条件不正确");
    }
    Ok((page, page_size, outcome.map(str::to_owned)))
}

pub(crate) async fn record_completed_login(
    pool: &Pool,
    context: &AuditContext,
    user_id: i32,
    username: &str,
    auth_method: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = pool.get().await?;
    let transaction = client.transaction().await?;
    let occurred_at = get_unix_epoch_ms();
    let source_ip: Option<IpAddr> = context.source_ip;
    let updated = transaction
        .execute(
            "UPDATE users SET last_login_at = $2, last_login_ip = $3, login_error_count = 0, \
             last_error_at = NULL, update_at = NOW() WHERE id = $1 AND disabled_at IS NULL \
             AND deleted_at IS NULL;",
            &[&user_id, &occurred_at, &source_ip],
        )
        .await?;
    if updated != 1 {
        return Err("登录用户已不存在或不可用".into());
    }

    let mut event = AuditEvent::anonymous("authentication", "auth.login", "success")
        .resource("user", user_id.to_string());
    event.severity = "info".to_owned();
    event.actor_type = "user".to_owned();
    event.actor_id = Some(user_id.to_string());
    event.actor_name = Some(username.to_owned());
    event.response_status = Some(200);
    event.metadata = json!({"auth_method": auth_method});
    write_audit(&transaction, context, &event).await?;
    transaction.commit().await?;
    Ok(())
}

pub(crate) fn login_failure_event(
    user: Option<&UserBaseI>,
    attempted_username: &str,
    reason_code: &str,
    auth_method: &str,
) -> AuditEvent {
    let attempted_username = attempted_username.chars().take(200).collect::<String>();
    let mut event = match user {
        Some(value) => AuditEvent::user("authentication", "auth.login", "failure", value),
        None => AuditEvent::anonymous("authentication", "auth.login", "failure"),
    };
    event.response_status = Some(401);
    event.reason_code = Some(reason_code.to_owned());
    event.metadata = json!({
        "attempted_username": attempted_username,
        "auth_method": auth_method
    });
    event
}

async fn list_login_records(
    req: &HttpRequest,
    pool: &Pool,
    actor: &UserBaseI,
    target_id: i32,
    target_username: &str,
    query: &LoginRecordQuery,
) -> HttpResponse {
    let (page, page_size, outcome) = match normalize_query(query) {
        Ok(value) => value,
        Err(message) => {
            return HttpResponse::BadRequest().json(json!({"success": false, "message": message}));
        }
    };
    let client = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => {
            error!(event = "LoginRecordPoolError", message = %error_value);
            return HttpResponse::InternalServerError()
                .json(json!({"success": false, "message": "登录记录服务暂时不可用"}));
        }
    };
    let actor_id = target_id.to_string();
    const FILTER: &str = "category = 'authentication' AND action = 'auth.login' \
        AND (actor_id = $1 OR (actor_id IS NULL AND \
             COALESCE(actor_name, metadata->>'attempted_username') = $2)) \
        AND ($3::TEXT IS NULL OR outcome = $3)";
    let total = match client
        .query_one(
            &format!("SELECT COUNT(*) AS total FROM audit_event WHERE {FILTER};"),
            &[&actor_id, &target_username, &outcome],
        )
        .await
    {
        Ok(row) => row.get::<_, i64>("total"),
        Err(error_value) => {
            error!(event = "LoginRecordCountError", message = %error_value);
            return HttpResponse::InternalServerError()
                .json(json!({"success": false, "message": "登录记录服务暂时不可用"}));
        }
    };
    let limit = i64::from(page_size);
    let offset = i64::from((page - 1) * page_size);
    let rows = match client
        .query(
            &format!(
                "SELECT event_id, occurred_at, outcome, source_ip::TEXT AS source_ip, user_agent, \
                 reason_code, COALESCE(metadata->>'auth_method', 'password') AS auth_method \
                 FROM audit_event WHERE {FILTER} ORDER BY occurred_at DESC, id DESC \
                 LIMIT $4 OFFSET $5;"
            ),
            &[&actor_id, &target_username, &outcome, &limit, &offset],
        )
        .await
    {
        Ok(value) => value,
        Err(error_value) => {
            error!(event = "LoginRecordQueryError", message = %error_value);
            return HttpResponse::InternalServerError()
                .json(json!({"success": false, "message": "登录记录服务暂时不可用"}));
        }
    };
    let records = rows
        .into_iter()
        .map(|row| LoginRecord {
            event_id: row.get("event_id"),
            occurred_at: row.get("occurred_at"),
            outcome: row.get("outcome"),
            source_ip: row.get("source_ip"),
            user_agent: row.get("user_agent"),
            reason_code: row.get("reason_code"),
            auth_method: row.get("auth_method"),
        })
        .collect::<Vec<_>>();
    let total_pages = if total == 0 {
        1
    } else {
        (total as u64).div_ceil(u64::from(page_size)) as u32
    };

    let mut audit_event = AuditEvent::user("audit", "user.login_records.query", "success", actor)
        .resource("user", target_id.to_string());
    audit_event.response_status = Some(200);
    audit_event.metadata = json!({"result_count": records.len()});
    write_standalone(pool, &AuditContext::from_request(req), &audit_event).await;

    HttpResponse::Ok().json(json!({
        "success": true,
        "data": records,
        "pagination": LoginRecordPagination { page, page_size, total, total_pages }
    }))
}

#[get("/api/user/login-records")]
pub async fn self_login_records(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    query: web::Query<LoginRecordQuery>,
) -> impl Responder {
    list_login_records(&req, pool.get_ref(), &user, user.id, &user.username, &query).await
}

#[get("/api/admin/users/{user_id}/login-records")]
pub async fn admin_login_records(
    req: HttpRequest,
    path: web::Path<i32>,
    pool: web::Data<Pool>,
    user: UserBaseI,
    query: web::Query<LoginRecordQuery>,
) -> impl Responder {
    if user.role != 1 {
        return HttpResponse::Forbidden()
            .json(json!({"success": false, "message": "仅管理员可以查看用户登录记录"}));
    }
    let target_id = path.into_inner();
    let client = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => {
            error!(event = "AdminLoginRecordPoolError", message = %error_value);
            return HttpResponse::InternalServerError()
                .json(json!({"success": false, "message": "登录记录服务暂时不可用"}));
        }
    };
    let target_username = match client
        .query_opt(
            "SELECT username FROM users WHERE id = $1 AND role IN (1, 2);",
            &[&target_id],
        )
        .await
    {
        Ok(Some(row)) => row.get::<_, String>("username"),
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(json!({"success": false, "message": "用户不存在"}));
        }
        Err(error_value) => {
            error!(event = "AdminLoginRecordTargetError", message = %error_value);
            return HttpResponse::InternalServerError()
                .json(json!({"success": false, "message": "登录记录服务暂时不可用"}));
        }
    };
    drop(client);
    list_login_records(
        &req,
        pool.get_ref(),
        &user,
        target_id,
        &target_username,
        &query,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::{LoginRecordQuery, normalize_query};

    #[test]
    fn login_record_query_is_bounded_and_validated() {
        let bounded = normalize_query(&LoginRecordQuery {
            page: Some(0),
            page_size: Some(500),
            outcome: Some("success".to_owned()),
        })
        .unwrap();
        assert_eq!(bounded, (1, 50, Some("success".to_owned())));

        assert!(
            normalize_query(&LoginRecordQuery {
                page: None,
                page_size: None,
                outcome: Some("denied".to_owned()),
            })
            .is_err()
        );
    }
}
