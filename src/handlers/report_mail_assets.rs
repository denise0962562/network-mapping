use crate::{
    admin::UserBaseI,
    audit::{self, AuditContext, AuditEvent},
    reports::assets,
};
use actix_web::{
    HttpRequest, HttpResponse,
    http::{Method, header},
    post, route, web,
};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use uuid::Uuid;

fn unavailable() -> HttpResponse {
    HttpResponse::NotFound()
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .finish()
}

#[route(
    "/mail/report-images/{token}/trend.png",
    method = "GET",
    method = "HEAD"
)]
pub(crate) async fn trend(
    req: HttpRequest,
    pool: web::Data<Pool>,
    token: web::Path<String>,
) -> HttpResponse {
    let Some(hash) = assets::token_hash(&token) else {
        return unavailable();
    };
    let result = async {
        let client = pool.get().await.map_err(|e| e.to_string())?;
        client.query_opt("SELECT a.png_bytes, a.sha256, a.expires_at FROM report_mail_asset a JOIN report_run r ON r.id = a.report_id WHERE a.token_hash = $1 AND a.revoked_at IS NULL AND a.expires_at > clock_timestamp() AND r.status = 'ready'", &[&hash]).await.map_err(|e| e.to_string())
    }.await;
    let row = match result {
        Ok(Some(row)) => row,
        Ok(None) => return unavailable(),
        Err(_) => {
            return HttpResponse::ServiceUnavailable()
                .insert_header((header::CACHE_CONTROL, "no-store"))
                .finish();
        }
    };
    let bytes: Vec<u8> = row.get("png_bytes");
    let etag = format!("\"{}\"", row.get::<_, String>("sha256"));
    let remaining = (row.get::<_, DateTime<Utc>>("expires_at") - Utc::now()).num_seconds();
    if remaining <= 0 {
        return unavailable();
    }
    let cached = req
        .headers()
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|tag| tag.trim().trim_start_matches("W/") == etag || tag.trim() == "*")
        });
    let mut response = if cached {
        HttpResponse::NotModified()
    } else {
        HttpResponse::Ok()
    };
    response
        .insert_header((
            header::CACHE_CONTROL,
            format!("private, max-age={}", remaining.min(3600)),
        ))
        .insert_header((header::ETAG, etag))
        .insert_header((header::X_CONTENT_TYPE_OPTIONS, "nosniff"));
    if cached {
        return response.finish();
    }
    response
        .content_type("image/png")
        .insert_header((header::CONTENT_LENGTH, bytes.len().to_string()));
    if req.method() == Method::HEAD {
        response.finish()
    } else {
        response.body(bytes)
    }
}

#[post("/api/reports/{id}/mail-image/revoke")]
pub(crate) async fn revoke(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    id: web::Path<Uuid>,
) -> HttpResponse {
    if user.role != 1 {
        return HttpResponse::Forbidden()
            .json(serde_json::json!({"success":false,"message":"仅管理员可以撤销报告图片"}));
    }
    let result = async {
        let mut client = pool.get().await.map_err(|e| e.to_string())?;
        let tx = client.transaction().await.map_err(|e| e.to_string())?;
        if tx.query_opt("SELECT id FROM report_run WHERE id = $1 FOR UPDATE", &[&*id]).await.map_err(|e| e.to_string())?.is_none() {
            return Ok::<_, String>(false);
        }
        let changed = tx.execute("UPDATE report_mail_asset SET revoked_at = COALESCE(revoked_at, NOW()) WHERE report_id = $1", &[&*id]).await.map_err(|e| e.to_string())?;
        if changed == 0 { return Ok(false); }
        tx.execute("UPDATE report_delivery SET status = 'cancelled', last_error = '报告趋势图片已撤销' WHERE report_id = $1 AND status = 'pending'", &[&*id]).await.map_err(|e| e.to_string())?;
        audit::write(&tx, &AuditContext::from_request(&req), &AuditEvent::user("data_access", "report.mail_image.revoke", "success", &user).resource("report", id.to_string())).await.map_err(|e| e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(true)
    }.await;
    match result {
        Ok(true) => HttpResponse::Ok().json(serde_json::json!({"success":true})),
        Ok(false) => unavailable(),
        Err(_) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"success":false,"message":"图片撤销失败，请稍后重试"})),
    }
}

/// Preview uses synthetic data only, and is never a capability URL for a real report.
#[route(
    "/mail/report-images/sample/trend.png",
    method = "GET",
    method = "HEAD"
)]
pub(crate) async fn sample(req: HttpRequest) -> HttpResponse {
    use std::sync::OnceLock;
    static IMAGE: OnceLock<Vec<u8>> = OnceLock::new();
    let bytes = if let Some(bytes) = IMAGE.get() {
        bytes.clone()
    } else {
        let items = match serde_json::from_value::<Vec<crate::reports::chart::TrendDay>>(
            crate::reports::mail_context::sample()["trend_rows"].clone(),
        ) {
            Ok(items) => items,
            Err(_) => return HttpResponse::ServiceUnavailable().finish(),
        };
        let result = crate::reports::chart::render_async(items).await;
        match result {
            Ok(bytes) => {
                let _ = IMAGE.set(bytes.clone());
                bytes
            }
            _ => return HttpResponse::ServiceUnavailable().finish(),
        }
    };
    let mut response = HttpResponse::Ok();
    response
        .content_type("image/png")
        .insert_header((header::CACHE_CONTROL, "public, max-age=3600"))
        .insert_header((header::CONTENT_LENGTH, bytes.len().to_string()));
    if req.method() == Method::HEAD {
        response.finish()
    } else {
        response.body(bytes)
    }
}
