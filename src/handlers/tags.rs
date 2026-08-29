use std::net::IpAddr;
use std::str::FromStr;

use crate::admin::UserBaseI;
use crate::audit::{AuditContext, AuditEvent, write as write_audit, write_standalone};
use crate::elasticsearch::ElasticsearchService;
use crate::logs::write::error_logs;
use crate::search_projection;
use actix_web::{HttpRequest, HttpResponse, Responder, delete, get, patch, post, web};
use deadpool_postgres::{Pool, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const MAX_TAGS_PER_IP: i64 = 20;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct AssetTag {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub description: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct CreateTagRequest {
    name: String,
    kind: String,
    description: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct UpdateTagRequest {
    name: String,
    kind: String,
    description: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct AssignTagRequest {
    ip: String,
    tag_id: i64,
}

#[derive(Deserialize)]
pub(crate) struct RemoveTagQuery {
    ip: String,
}

struct ValidatedTag {
    name: String,
    kind: String,
    description: Option<String>,
}

fn normalize_ip(value: &str) -> Result<String, &'static str> {
    IpAddr::from_str(value.trim())
        .map(|address| address.to_string())
        .map_err(|_| "IP 地址格式无效")
}

fn validate_tag(
    name: &str,
    kind: &str,
    description: Option<&str>,
) -> Result<ValidatedTag, &'static str> {
    let name = name.trim();
    if !(1..=32).contains(&name.chars().count()) {
        return Err("标签名称长度必须在 1 到 32 个字符之间");
    }
    if !matches!(kind, "info" | "malicious" | "benign") {
        return Err("标签类型无效");
    }
    let description = description.map(str::trim).filter(|value| !value.is_empty());
    if description.is_some_and(|value| value.chars().count() > 256) {
        return Err("标签描述不能超过 256 个字符");
    }
    Ok(ValidatedTag {
        name: name.to_owned(),
        kind: kind.to_owned(),
        description: description.map(str::to_owned),
    })
}

fn tag_from_row(row: &tokio_postgres::Row) -> AssetTag {
    AssetTag {
        id: row.get("id"),
        name: row.get("name"),
        kind: row.get("kind"),
        description: row.get("description"),
    }
}

pub(crate) fn tags_from_json(value: Value) -> Vec<AssetTag> {
    serde_json::from_value(value).unwrap_or_default()
}

fn database_error(
    req: &HttpRequest,
    event: &str,
    error_value: &dyn std::fmt::Display,
) -> HttpResponse {
    error_logs(req, event, &error_value.to_string());
    HttpResponse::InternalServerError()
        .json(json!({"success": false, "message": "标签服务暂时不可用"}))
}

async fn deny_non_admin(
    req: &HttpRequest,
    pool: &Pool,
    user: &UserBaseI,
    action: &str,
) -> Option<HttpResponse> {
    if user.role == 1 {
        return None;
    }
    let mut event = AuditEvent::user("authorization", action, "denied", user);
    event.response_status = Some(403);
    event.reason_code = Some("insufficient_role".to_owned());
    write_standalone(pool, &AuditContext::from_request(req), &event).await;
    Some(HttpResponse::Forbidden().json(json!({
        "success": false,
        "message": "仅管理员可以管理资产标签"
    })))
}

async fn audit_change(
    transaction: &Transaction<'_>,
    req: &HttpRequest,
    user: &UserBaseI,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    changes: Value,
) -> Result<(), tokio_postgres::Error> {
    let mut event = AuditEvent::user("data_access", action, "success", user)
        .resource(resource_type, resource_id);
    if resource_type == "asset_tag" {
        event.category = "configuration".to_owned();
    }
    event.response_status = Some(200);
    event.changes = Some(changes);
    write_audit(transaction, &AuditContext::from_request(req), &event).await
}

async fn active_tag(
    transaction: &Transaction<'_>,
    tag_id: i64,
) -> Result<Option<AssetTag>, tokio_postgres::Error> {
    transaction
        .query_opt(
            "SELECT id, name, kind, description FROM asset_tag WHERE id = $1 AND is_active FOR UPDATE;",
            &[&tag_id],
        )
        .await
        .map(|row| row.as_ref().map(tag_from_row))
}

async fn has_classification_conflict(
    transaction: &Transaction<'_>,
    ip: &str,
    kind: &str,
    excluding_tag_id: Option<i64>,
) -> Result<bool, tokio_postgres::Error> {
    let opposite = match kind {
        "malicious" => "benign",
        "benign" => "malicious",
        _ => return Ok(false),
    };
    transaction
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM asset_ip_tag assignment \
             JOIN asset_tag tag ON tag.id = assignment.tag_id \
             WHERE assignment.ip_address = $1::TEXT::INET AND tag.is_active \
               AND tag.kind = $2 AND ($3::BIGINT IS NULL OR tag.id <> $3)) AS conflict;",
            &[&ip, &opposite, &excluding_tag_id],
        )
        .await
        .map(|row| row.get("conflict"))
}

#[get("/api/tags")]
pub(crate) async fn list_tags(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
) -> impl Responder {
    let connection = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "ListTagsPoolError", &error_value),
    };
    let rows = match connection
        .query(
            "SELECT id, name, kind, description FROM asset_tag WHERE is_active \
             ORDER BY CASE kind WHEN 'malicious' THEN 1 WHEN 'benign' THEN 2 ELSE 3 END, LOWER(name), id;",
            &[],
        )
        .await
    {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "ListTagsQueryError", &error_value),
    };
    let items: Vec<AssetTag> = rows.iter().map(tag_from_row).collect();
    HttpResponse::Ok().json(json!({
        "success": true,
        "data": {"items": items, "can_manage": user.role == 1}
    }))
}

#[post("/api/tags")]
pub(crate) async fn create_tag(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    payload: web::Json<CreateTagRequest>,
) -> impl Responder {
    if let Some(response) = deny_non_admin(&req, pool.get_ref(), &user, "asset.tag.create").await {
        return response;
    }
    let tag = match validate_tag(&payload.name, &payload.kind, payload.description.as_deref()) {
        Ok(value) => value,
        Err(message) => {
            return HttpResponse::BadRequest().json(json!({"success": false, "message": message}));
        }
    };
    let mut connection = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "CreateTagPoolError", &error_value),
    };
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "CreateTagTransactionError", &error_value),
    };
    let row = match transaction
        .query_opt(
            "INSERT INTO asset_tag (name, kind, description, created_by) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (LOWER(name)) WHERE is_active DO NOTHING \
             RETURNING id, name, kind, description;",
            &[&tag.name, &tag.kind, &tag.description, &user.id],
        )
        .await
    {
        Ok(Some(value)) => value,
        Ok(None) => {
            return HttpResponse::Conflict()
                .json(json!({"success": false, "message": "标签名称已存在"}));
        }
        Err(error_value) => return database_error(&req, "CreateTagQueryError", &error_value),
    };
    let created = tag_from_row(&row);
    if let Err(error_value) = audit_change(
        &transaction,
        &req,
        &user,
        "asset.tag.create",
        "asset_tag",
        &created.id.to_string(),
        json!({"name": created.name, "kind": created.kind, "description": created.description}),
    )
    .await
    {
        return database_error(&req, "CreateTagAuditError", &error_value);
    }
    if let Err(error_value) = transaction.commit().await {
        return database_error(&req, "CreateTagCommitError", &error_value);
    }
    HttpResponse::Created().json(json!({"success": true, "data": {"tag": created}}))
}

#[patch("/api/tags/{tag_id}")]
pub(crate) async fn update_tag(
    req: HttpRequest,
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    user: UserBaseI,
    tag_id: web::Path<i64>,
    payload: web::Json<UpdateTagRequest>,
) -> impl Responder {
    if let Some(response) = deny_non_admin(&req, pool.get_ref(), &user, "asset.tag.update").await {
        return response;
    }
    let tag_id = tag_id.into_inner();
    let tag = match validate_tag(&payload.name, &payload.kind, payload.description.as_deref()) {
        Ok(value) => value,
        Err(message) => {
            return HttpResponse::BadRequest().json(json!({"success": false, "message": message}));
        }
    };
    let mut connection = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "UpdateTagPoolError", &error_value),
    };
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "UpdateTagTransactionError", &error_value),
    };
    let previous = match active_tag(&transaction, tag_id).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(json!({"success": false, "message": "标签不存在"}));
        }
        Err(error_value) => return database_error(&req, "UpdateTagLookupError", &error_value),
    };
    let assigned_ips = match transaction
        .query(
            "SELECT host(ip_address) AS ip FROM asset_ip_tag WHERE tag_id = $1;",
            &[&tag_id],
        )
        .await
    {
        Ok(rows) => rows
            .into_iter()
            .map(|row| row.get::<_, String>("ip"))
            .collect::<Vec<_>>(),
        Err(error_value) => {
            return database_error(&req, "UpdateTagAssignmentsLookupError", &error_value);
        }
    };
    let duplicate: bool = match transaction
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM asset_tag WHERE is_active AND id <> $1 AND LOWER(name) = LOWER($2)) AS duplicate;",
            &[&tag_id, &tag.name],
        )
        .await
    {
        Ok(row) => row.get("duplicate"),
        Err(error_value) => return database_error(&req, "UpdateTagDuplicateError", &error_value),
    };
    if duplicate {
        return HttpResponse::Conflict()
            .json(json!({"success": false, "message": "标签名称已存在"}));
    }
    if matches!(tag.kind.as_str(), "malicious" | "benign") {
        let conflict = match transaction
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM asset_ip_tag current_assignment \
                 JOIN asset_ip_tag opposite_assignment ON opposite_assignment.ip_address = current_assignment.ip_address \
                 JOIN asset_tag opposite ON opposite.id = opposite_assignment.tag_id AND opposite.is_active \
                 WHERE current_assignment.tag_id = $1 AND opposite.id <> $1 AND opposite.kind = $2) AS conflict;",
                &[&tag_id, &if tag.kind == "malicious" { "benign" } else { "malicious" }],
            )
            .await
        {
            Ok(row) => row.get("conflict"),
            Err(error_value) => return database_error(&req, "UpdateTagConflictError", &error_value),
        };
        if conflict {
            return HttpResponse::Conflict().json(
                json!({"success": false, "message": "部分 IP 已绑定相反分类，请先移除冲突标签"}),
            );
        }
    }
    let row = match transaction
        .query_one(
            "UPDATE asset_tag SET name = $1, kind = $2, description = $3, updated_at = NOW() \
             WHERE id = $4 RETURNING id, name, kind, description;",
            &[&tag.name, &tag.kind, &tag.description, &tag_id],
        )
        .await
    {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "UpdateTagQueryError", &error_value),
    };
    let updated = tag_from_row(&row);
    if let Err(error_value) = search_projection::enqueue_tag_assignments(&transaction, tag_id).await
    {
        return database_error(&req, "UpdateTagSearchOutboxError", &error_value);
    }
    if let Err(error_value) = audit_change(
        &transaction,
        &req,
        &user,
        "asset.tag.update",
        "asset_tag",
        &tag_id.to_string(),
        json!({"before": previous, "after": updated}),
    )
    .await
    {
        return database_error(&req, "UpdateTagAuditError", &error_value);
    }
    if let Err(error_value) = transaction.commit().await {
        return database_error(&req, "UpdateTagCommitError", &error_value);
    }
    if elasticsearch.scan_storage_mode().writes_elasticsearch()
        && let Err(error) =
            refresh_elasticsearch_tag_ips(pool.get_ref(), elasticsearch.get_ref(), &assigned_ips)
                .await
    {
        error_logs(&req, "UpdateTagElasticsearchProjectionError", &error);
        return HttpResponse::ServiceUnavailable()
            .json(json!({"success": false, "message": "标签已更新，但搜索投影更新失败"}));
    }
    HttpResponse::Ok().json(json!({"success": true, "data": {"tag": updated}}))
}

#[delete("/api/tags/{tag_id}")]
pub(crate) async fn delete_tag(
    req: HttpRequest,
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    user: UserBaseI,
    tag_id: web::Path<i64>,
) -> impl Responder {
    if let Some(response) = deny_non_admin(&req, pool.get_ref(), &user, "asset.tag.delete").await {
        return response;
    }
    let tag_id = tag_id.into_inner();
    let mut connection = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "DeleteTagPoolError", &error_value),
    };
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "DeleteTagTransactionError", &error_value),
    };
    let tag = match active_tag(&transaction, tag_id).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(json!({"success": false, "message": "标签不存在"}));
        }
        Err(error_value) => return database_error(&req, "DeleteTagLookupError", &error_value),
    };
    let assigned_ips = match transaction
        .query(
            "SELECT host(ip_address) AS ip FROM asset_ip_tag WHERE tag_id = $1;",
            &[&tag_id],
        )
        .await
    {
        Ok(rows) => rows
            .into_iter()
            .map(|row| row.get::<_, String>("ip"))
            .collect::<Vec<_>>(),
        Err(error_value) => {
            return database_error(&req, "DeleteTagAssignmentsLookupError", &error_value);
        }
    };
    if let Err(error_value) = search_projection::enqueue_tag_assignments(&transaction, tag_id).await
    {
        return database_error(&req, "DeleteTagSearchOutboxError", &error_value);
    }
    let removed_assignments = match transaction
        .execute("DELETE FROM asset_ip_tag WHERE tag_id = $1;", &[&tag_id])
        .await
    {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "DeleteTagAssignmentsError", &error_value),
    };
    if let Err(error_value) = transaction
        .execute(
            "UPDATE asset_tag SET is_active = FALSE, updated_at = NOW() WHERE id = $1;",
            &[&tag_id],
        )
        .await
    {
        return database_error(&req, "DeleteTagQueryError", &error_value);
    }
    if let Err(error_value) = audit_change(
        &transaction,
        &req,
        &user,
        "asset.tag.delete",
        "asset_tag",
        &tag_id.to_string(),
        json!({"tag": tag, "removed_assignments": removed_assignments}),
    )
    .await
    {
        return database_error(&req, "DeleteTagAuditError", &error_value);
    }
    if let Err(error_value) = transaction.commit().await {
        return database_error(&req, "DeleteTagCommitError", &error_value);
    }
    if elasticsearch.scan_storage_mode().writes_elasticsearch()
        && let Err(error) =
            refresh_elasticsearch_tag_ips(pool.get_ref(), elasticsearch.get_ref(), &assigned_ips)
                .await
    {
        error_logs(&req, "DeleteTagElasticsearchProjectionError", &error);
        return HttpResponse::ServiceUnavailable()
            .json(json!({"success": false, "message": "标签已删除，但搜索投影更新失败"}));
    }
    HttpResponse::Ok().json(json!({"success": true}))
}

#[post("/api/assets/tags")]
pub(crate) async fn assign_tag(
    req: HttpRequest,
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    user: UserBaseI,
    payload: web::Json<AssignTagRequest>,
) -> impl Responder {
    if let Some(response) = deny_non_admin(&req, pool.get_ref(), &user, "asset.tag.assign").await {
        return response;
    }
    let ip = match normalize_ip(&payload.ip) {
        Ok(value) => value,
        Err(message) => {
            return HttpResponse::BadRequest().json(json!({"success": false, "message": message}));
        }
    };
    let mut connection = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "AssignTagPoolError", &error_value),
    };
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "AssignTagTransactionError", &error_value),
    };
    let exists = if elasticsearch.scan_storage_mode().reads_elasticsearch() {
        match elasticsearch.scan_asset_exists(&ip).await {
            Ok(value) => value,
            Err(error) => {
                error_logs(&req, "AssignTagAssetElasticsearchError", &error);
                return HttpResponse::ServiceUnavailable()
                    .json(json!({"success": false, "message": "扫描结果索引暂时不可用"}));
            }
        }
    } else {
        match transaction
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM scan_observation observation \
                 JOIN scan_task_execution execution ON execution.id = observation.execution_id \
                 WHERE observation.ip_address = $1::TEXT::INET AND execution.execution_status = 'succeeded') AS exists;",
                &[&ip],
            )
            .await
        {
            Ok(row) => row.get("exists"),
            Err(error_value) => return database_error(&req, "AssignTagAssetLookupError", &error_value),
        }
    };
    if !exists {
        return HttpResponse::NotFound().json(json!({"success": false, "message": "资产不存在"}));
    }
    let tag = match active_tag(&transaction, payload.tag_id).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(json!({"success": false, "message": "标签不存在"}));
        }
        Err(error_value) => return database_error(&req, "AssignTagLookupError", &error_value),
    };
    if let Err(error_value) = transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0));",
            &[&ip],
        )
        .await
    {
        return database_error(&req, "AssignTagLockError", &error_value);
    }
    let existing: bool = match transaction
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM asset_ip_tag WHERE ip_address = $1::TEXT::INET AND tag_id = $2) AS exists;",
            &[&ip, &tag.id],
        )
        .await
    {
        Ok(row) => row.get("exists"),
        Err(error_value) => return database_error(&req, "AssignTagExistingError", &error_value),
    };
    if existing {
        return HttpResponse::Ok()
            .json(json!({"success": true, "data": {"tag": tag, "created": false}}));
    }
    let count: i64 = match transaction
        .query_one(
            "SELECT COUNT(*)::BIGINT AS count FROM asset_ip_tag assignment \
             JOIN asset_tag current_tag ON current_tag.id = assignment.tag_id AND current_tag.is_active \
             WHERE assignment.ip_address = $1::TEXT::INET;",
            &[&ip],
        )
        .await
    {
        Ok(row) => row.get("count"),
        Err(error_value) => return database_error(&req, "AssignTagCountError", &error_value),
    };
    if count >= MAX_TAGS_PER_IP {
        return HttpResponse::Conflict()
            .json(json!({"success": false, "message": "单个 IP 最多绑定 20 个标签"}));
    }
    let conflict = match has_classification_conflict(&transaction, &ip, &tag.kind, None).await {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "AssignTagConflictError", &error_value),
    };
    if conflict {
        return HttpResponse::Conflict()
            .json(json!({"success": false, "message": "恶意与正常标签不能同时绑定"}));
    }
    if let Err(error_value) = transaction
        .execute(
            "INSERT INTO asset_ip_tag (ip_address, tag_id, assigned_by) VALUES ($1::TEXT::INET, $2, $3);",
            &[&ip, &tag.id, &user.id],
        )
        .await
    {
        return database_error(&req, "AssignTagQueryError", &error_value);
    }
    if let Err(error_value) = search_projection::enqueue_ip(&transaction, &ip).await {
        return database_error(&req, "AssignTagSearchOutboxError", &error_value);
    }
    if let Err(error_value) = audit_change(
        &transaction,
        &req,
        &user,
        "asset.tag.assign",
        "ip_asset",
        &ip,
        json!({"tag": tag}),
    )
    .await
    {
        return database_error(&req, "AssignTagAuditError", &error_value);
    }
    if let Err(error_value) = transaction.commit().await {
        return database_error(&req, "AssignTagCommitError", &error_value);
    }
    if elasticsearch.scan_storage_mode().writes_elasticsearch()
        && let Err(error) =
            refresh_elasticsearch_tags(pool.get_ref(), elasticsearch.get_ref(), &ip).await
    {
        error_logs(&req, "AssignTagElasticsearchProjectionError", &error);
        return HttpResponse::ServiceUnavailable()
            .json(json!({"success": false, "message": "标签已保存，但搜索投影更新失败"}));
    }
    HttpResponse::Created().json(json!({"success": true, "data": {"tag": tag, "created": true}}))
}

#[delete("/api/assets/tags/{tag_id}")]
pub(crate) async fn remove_tag(
    req: HttpRequest,
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    user: UserBaseI,
    tag_id: web::Path<i64>,
    query: web::Query<RemoveTagQuery>,
) -> impl Responder {
    if let Some(response) = deny_non_admin(&req, pool.get_ref(), &user, "asset.tag.remove").await {
        return response;
    }
    let ip = match normalize_ip(&query.ip) {
        Ok(value) => value,
        Err(message) => {
            return HttpResponse::BadRequest().json(json!({"success": false, "message": message}));
        }
    };
    let tag_id = tag_id.into_inner();
    let mut connection = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "RemoveTagPoolError", &error_value),
    };
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "RemoveTagTransactionError", &error_value),
    };
    let tag = match active_tag(&transaction, tag_id).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(json!({"success": false, "message": "标签不存在"}));
        }
        Err(error_value) => return database_error(&req, "RemoveTagLookupError", &error_value),
    };
    let removed = match transaction
        .execute(
            "DELETE FROM asset_ip_tag WHERE ip_address = $1::TEXT::INET AND tag_id = $2;",
            &[&ip, &tag_id],
        )
        .await
    {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "RemoveTagQueryError", &error_value),
    };
    if removed == 0 {
        return HttpResponse::NotFound()
            .json(json!({"success": false, "message": "IP 未绑定该标签"}));
    }
    if let Err(error_value) = search_projection::enqueue_ip(&transaction, &ip).await {
        return database_error(&req, "RemoveTagSearchOutboxError", &error_value);
    }
    if let Err(error_value) = audit_change(
        &transaction,
        &req,
        &user,
        "asset.tag.remove",
        "ip_asset",
        &ip,
        json!({"tag": tag}),
    )
    .await
    {
        return database_error(&req, "RemoveTagAuditError", &error_value);
    }
    if let Err(error_value) = transaction.commit().await {
        return database_error(&req, "RemoveTagCommitError", &error_value);
    }
    if elasticsearch.scan_storage_mode().writes_elasticsearch()
        && let Err(error) =
            refresh_elasticsearch_tags(pool.get_ref(), elasticsearch.get_ref(), &ip).await
    {
        error_logs(&req, "RemoveTagElasticsearchProjectionError", &error);
        return HttpResponse::ServiceUnavailable()
            .json(json!({"success": false, "message": "标签已删除，但搜索投影更新失败"}));
    }
    HttpResponse::Ok().json(json!({"success": true}))
}

async fn refresh_elasticsearch_tags(
    pool: &Pool,
    elasticsearch: &ElasticsearchService,
    ip: &str,
) -> Result<(), String> {
    let connection = pool.get().await.map_err(|error| error.to_string())?;
    let rows = connection
        .query(
            "SELECT tag.id, tag.name, tag.kind, tag.description \
             FROM asset_ip_tag assignment JOIN asset_tag tag ON tag.id = assignment.tag_id \
             WHERE assignment.ip_address = $1::TEXT::INET AND tag.is_active ORDER BY tag.id;",
            &[&ip],
        )
        .await
        .map_err(|error| error.to_string())?;
    let tags = rows.iter().map(tag_from_row).collect::<Vec<_>>();
    elasticsearch.refresh_scan_asset_tags(ip, &tags).await
}

async fn refresh_elasticsearch_tag_ips(
    pool: &Pool,
    elasticsearch: &ElasticsearchService,
    ips: &[String],
) -> Result<(), String> {
    for ip in ips {
        refresh_elasticsearch_tags(pool, elasticsearch, ip).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{normalize_ip, tags_from_json, validate_tag};
    use serde_json::json;

    #[test]
    fn normalizes_ipv4_and_ipv6_addresses() {
        assert_eq!(normalize_ip(" 192.0.2.1 "), Ok("192.0.2.1".to_owned()));
        assert_eq!(
            normalize_ip("2001:0db8:0:0:0:0:0:1"),
            Ok("2001:db8::1".to_owned())
        );
    }

    #[test]
    fn validates_tag_fields() {
        assert!(validate_tag("办公出口", "info", Some("说明")).is_ok());
        assert!(validate_tag("", "info", None).is_err());
        assert!(validate_tag("标签", "unknown", None).is_err());
        assert!(validate_tag("标签", "info", Some(&"a".repeat(257))).is_err());
    }

    #[test]
    fn parses_aggregated_tags() {
        let tags = tags_from_json(json!([{
            "id": 1,
            "name": "可信",
            "kind": "benign",
            "description": null
        }]));
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].kind, "benign");
    }
}
