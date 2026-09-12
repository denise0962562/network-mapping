use std::net::IpAddr;

use actix_web::{HttpRequest, HttpResponse, Responder, get, put, web};
use cidr::IpCidr;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::admin::UserBaseI;
use crate::audit::{AuditContext, AuditEvent, write as write_audit};
use crate::client_ip::{display_ip, request_ip};
use crate::login_allowlist::{
    MAX_LOGIN_ALLOWLIST_ENTRIES, display_login_allowlist, load_login_allowlist,
    normalize_login_allowlist,
};
use crate::logs::write::error_logs_error;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateLoginAllowlistRequest {
    entries: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginAllowlistData {
    enabled: bool,
    entries: Vec<String>,
    current_ip: Option<String>,
}

fn response_data(allowlist: &[IpCidr], source_ip: Option<IpAddr>) -> serde_json::Value {
    json!({
        "success": true,
        "data": LoginAllowlistData {
            enabled: !allowlist.is_empty(),
            entries: display_login_allowlist(allowlist),
            current_ip: display_ip(source_ip),
        },
        "limits": {
            "maximumEntries": MAX_LOGIN_ALLOWLIST_ENTRIES,
        }
    })
}

#[get("/api/user/security/login-ip-allowlist")]
pub(crate) async fn get_login_ip_allowlist(
    req: HttpRequest,
    pool: web::Data<deadpool_postgres::Pool>,
    user: UserBaseI,
) -> impl Responder {
    match load_login_allowlist(pool.get_ref(), user.id).await {
        Ok(allowlist) => HttpResponse::Ok().json(response_data(&allowlist, request_ip(&req))),
        Err(error_value) => {
            error_logs_error(
                &req,
                "GetLoginIpAllowlistError",
                "load_login_ip_allowlist",
                error_value.as_ref(),
            );
            HttpResponse::InternalServerError()
                .json(json!({"success": false, "message": "登录白名单加载失败"}))
        }
    }
}

#[put("/api/user/security/login-ip-allowlist")]
pub(crate) async fn update_login_ip_allowlist(
    req: HttpRequest,
    pool: web::Data<deadpool_postgres::Pool>,
    user: UserBaseI,
    body: web::Json<UpdateLoginAllowlistRequest>,
) -> impl Responder {
    let allowlist = match normalize_login_allowlist(&body.entries) {
        Ok(value) => value,
        Err(error_value) => {
            return HttpResponse::BadRequest()
                .json(json!({"success": false, "message": error_value.to_string()}));
        }
    };

    let mut connection = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => {
            error_logs_error(
                &req,
                "UpdateLoginIpAllowlistPoolError",
                "acquire_login_ip_allowlist_connection",
                &error_value,
            );
            return HttpResponse::InternalServerError()
                .json(json!({"success": false, "message": "登录白名单保存失败"}));
        }
    };
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(error_value) => {
            error_logs_error(
                &req,
                "UpdateLoginIpAllowlistTransactionError",
                "begin_login_ip_allowlist_update",
                &error_value,
            );
            return HttpResponse::InternalServerError()
                .json(json!({"success": false, "message": "登录白名单保存失败"}));
        }
    };

    let result: Result<Vec<IpCidr>, tokio_postgres::Error> = async {
        let old_allowlist: Vec<IpCidr> = transaction
            .query_one(
                "SELECT login_ip_allowlist FROM users WHERE id = $1 AND disabled_at IS NULL AND deleted_at IS NULL FOR UPDATE;",
                &[&user.id],
            )
            .await?
            .get("login_ip_allowlist");
        transaction
            .execute(
                "UPDATE users SET login_ip_allowlist = $2, update_at = NOW() WHERE id = $1;",
                &[&user.id, &allowlist],
            )
            .await?;

        let mut event = AuditEvent::user(
            "user_security",
            "user.login_ip_allowlist_update",
            "success",
            &user,
        )
        .resource("user", user.id.to_string());
        event.response_status = Some(200);
        event.changes = Some(json!({
            "login_ip_allowlist": {
                "old": display_login_allowlist(&old_allowlist),
                "new": display_login_allowlist(&allowlist),
            }
        }));
        write_audit(&transaction, &AuditContext::from_request(&req), &event).await?;
        transaction.commit().await?;
        Ok(allowlist)
    }
    .await;

    match result {
        Ok(saved) => HttpResponse::Ok().json(response_data(&saved, request_ip(&req))),
        Err(error_value) => {
            error_logs_error(
                &req,
                "UpdateLoginIpAllowlistError",
                "update_login_ip_allowlist",
                &error_value,
            );
            HttpResponse::InternalServerError()
                .json(json!({"success": false, "message": "登录白名单保存失败"}))
        }
    }
}

#[get("/api/admin/users/{user_id}/login-ip-allowlist")]
pub(crate) async fn get_managed_login_ip_allowlist(
    req: HttpRequest,
    pool: web::Data<deadpool_postgres::Pool>,
    actor: UserBaseI,
    user_id: web::Path<i32>,
) -> impl Responder {
    if actor.role != 1 {
        return HttpResponse::Forbidden()
            .json(json!({"success": false, "message": "仅管理员可以管理用户"}));
    }
    let connection = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => {
            error_logs_error(
                &req,
                "GetManagedLoginIpAllowlistPoolError",
                "acquire_managed_login_ip_allowlist_connection",
                &error_value,
            );
            return HttpResponse::InternalServerError()
                .json(json!({"success": false, "message": "登录白名单加载失败"}));
        }
    };
    match connection
        .query_opt(
            "SELECT login_ip_allowlist FROM users WHERE id = $1 AND deleted_at IS NULL LIMIT 1;",
            &[&user_id.into_inner()],
        )
        .await
    {
        Ok(Some(row)) => {
            let allowlist: Vec<IpCidr> = row.get("login_ip_allowlist");
            HttpResponse::Ok().json(response_data(&allowlist, request_ip(&req)))
        }
        Ok(None) => {
            HttpResponse::NotFound().json(json!({"success": false, "message": "用户不存在"}))
        }
        Err(error_value) => {
            error_logs_error(
                &req,
                "GetManagedLoginIpAllowlistError",
                "load_managed_login_ip_allowlist",
                &error_value,
            );
            HttpResponse::InternalServerError()
                .json(json!({"success": false, "message": "登录白名单加载失败"}))
        }
    }
}

#[put("/api/admin/users/{user_id}/login-ip-allowlist")]
pub(crate) async fn update_managed_login_ip_allowlist(
    req: HttpRequest,
    pool: web::Data<deadpool_postgres::Pool>,
    actor: UserBaseI,
    user_id: web::Path<i32>,
    body: web::Json<UpdateLoginAllowlistRequest>,
) -> impl Responder {
    if actor.role != 1 {
        return HttpResponse::Forbidden()
            .json(json!({"success": false, "message": "仅管理员可以管理用户"}));
    }
    let allowlist = match normalize_login_allowlist(&body.entries) {
        Ok(value) => value,
        Err(error_value) => {
            return HttpResponse::BadRequest()
                .json(json!({"success": false, "message": error_value.to_string()}));
        }
    };
    let user_id = user_id.into_inner();
    let mut connection = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => {
            error_logs_error(
                &req,
                "UpdateManagedLoginIpAllowlistPoolError",
                "acquire_managed_login_ip_allowlist_connection",
                &error_value,
            );
            return HttpResponse::InternalServerError()
                .json(json!({"success": false, "message": "登录白名单保存失败"}));
        }
    };
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(error_value) => {
            error_logs_error(
                &req,
                "UpdateManagedLoginIpAllowlistTransactionError",
                "begin_managed_login_ip_allowlist_update",
                &error_value,
            );
            return HttpResponse::InternalServerError()
                .json(json!({"success": false, "message": "登录白名单保存失败"}));
        }
    };

    let row = match transaction
        .query_opt(
            "SELECT username, login_ip_allowlist FROM users WHERE id = $1 AND deleted_at IS NULL FOR UPDATE;",
            &[&user_id],
        )
        .await
    {
        Ok(Some(value)) => value,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(json!({"success": false, "message": "用户不存在"}));
        }
        Err(error_value) => {
            error_logs_error(
                &req,
                "UpdateManagedLoginIpAllowlistReadError",
                "read_managed_login_ip_allowlist",
                &error_value,
            );
            return HttpResponse::InternalServerError()
                .json(json!({"success": false, "message": "登录白名单保存失败"}));
        }
    };
    let username: String = row.get("username");
    let old_allowlist: Vec<IpCidr> = row.get("login_ip_allowlist");
    if let Err(error_value) = transaction
        .execute(
            "UPDATE users SET login_ip_allowlist = $2, update_at = NOW() WHERE id = $1;",
            &[&user_id, &allowlist],
        )
        .await
    {
        error_logs_error(
            &req,
            "UpdateManagedLoginIpAllowlistWriteError",
            "write_managed_login_ip_allowlist",
            &error_value,
        );
        return HttpResponse::InternalServerError()
            .json(json!({"success": false, "message": "登录白名单保存失败"}));
    }
    let mut event = AuditEvent::user(
        "user_security",
        "admin.user_login_ip_allowlist_update",
        "success",
        &actor,
    )
    .resource("user", user_id.to_string());
    event.response_status = Some(200);
    event.changes = Some(json!({
        "username": username,
        "login_ip_allowlist": {
            "old": display_login_allowlist(&old_allowlist),
            "new": display_login_allowlist(&allowlist),
        }
    }));
    if let Err(error_value) =
        write_audit(&transaction, &AuditContext::from_request(&req), &event).await
    {
        error_logs_error(
            &req,
            "UpdateManagedLoginIpAllowlistAuditError",
            "audit_managed_login_ip_allowlist_update",
            &error_value,
        );
        return HttpResponse::InternalServerError()
            .json(json!({"success": false, "message": "登录白名单保存失败"}));
    }
    if let Err(error_value) = transaction.commit().await {
        error_logs_error(
            &req,
            "UpdateManagedLoginIpAllowlistCommitError",
            "commit_managed_login_ip_allowlist_update",
            &error_value,
        );
        return HttpResponse::InternalServerError()
            .json(json!({"success": false, "message": "登录白名单保存失败"}));
    }

    HttpResponse::Ok().json(response_data(&allowlist, request_ip(&req)))
}
