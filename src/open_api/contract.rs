//! The machine-readable contract is generated from the same route allowlist as dispatch.
use super::{catalog::Endpoint, model};
use serde_json::{Value, json};

fn object(properties: Value, required: &[&str]) -> Value {
    json!({"type":"object","additionalProperties":false,"properties":properties,"required":required})
}
fn strings(max: usize) -> Value {
    json!({"type":"array","maxItems":max,"items":{"type":"string"}})
}
fn reference(name: &str) -> Value {
    json!({"$ref":format!("#/components/schemas/{name}")})
}
pub(super) fn schemas() -> Value {
    let fields = json!({"type":"array","minItems":1,"maxItems":model::FIELDS.len(),"items":{"type":"string","enum":model::FIELDS}});
    let page = json!({"type":"integer","minimum":1,"maximum":100,"default":50});
    let cursor = json!({"type":"string","format":"uuid","description":"不透明游标，绑定应用、凭据、策略版本和原查询；10 分钟有效"});
    let input_time = json!({"oneOf":[{"type":"string","format":"date-time"},{"type":"integer","format":"int64"}],"description":"推荐 RFC 3339 含时区；兼容 UTC 毫秒时间戳。开始含、结束不含"});
    let mut endpoint = serde_json::Map::new();
    for field in model::FIELDS {
        endpoint.insert((*field).into(),if *field=="port" {json!({"type":"integer","minimum":1,"maximum":65535})}else if *field=="tags" {json!({"type":"array","items":{"type":"object","properties":{"id":{"type":"integer","format":"int64"},"name":{"type":"string"}}}})}else{json!({"description":"仅在批准的字段白名单内且有观察值时返回"})});
    }
    json!({
        "InputTime":input_time,
        "Fields":fields,
        "Endpoint":{"type":"object","additionalProperties":false,"properties":endpoint},
        "Envelope":{"type":"object","required":["data","request_id"],"properties":{"data":{"type":"object"},"request_id":{"type":"string","format":"uuid"}}},
        "Error":{"type":"object","required":["error","request_id"],"properties":{"error":{"type":"object","required":["code","message"],"properties":{"code":{"type":"string"},"message":{"type":"string"}}},"request_id":{"type":"string","format":"uuid"}}},
        "Page":{"type":"object","required":["items"],"properties":{"items":{"type":"array","items":{"type":"object"}},"next_cursor":{"type":["string","null"],"format":"uuid"}}},
        "AssetSearch":object(json!({"query":{"type":"string","maxLength":2048,"default":""},"page_size":page,"cursor":cursor,"fields":reference("Fields"),"start_at":reference("InputTime"),"end_at":reference("InputTime")}), &[]),
        "ObservationSearch":object(json!({"page_size":page,"cursor":cursor,"start_at":reference("InputTime"),"end_at":reference("InputTime"),"task_id":{"type":"string","format":"uuid"},"execution_id":{"type":"string","format":"uuid"}}),&[]),
        "VulnerabilitySearch":object(json!({"page_size":page,"cursor":cursor,"start_at":reference("InputTime"),"end_at":reference("InputTime"),"task_id":{"type":"string","format":"uuid"},"execution_id":{"type":"string","format":"uuid"},"severity":{"type":"string","enum":["info","low","medium","high","critical"]},"template_id":{"type":"string"}}),&[]),
        "TaskInput":object(json!({"targets":strings(65536),"domains":strings(100),"ports":{"type":"string","maxLength":4096,"default":"80,443","description":"逗号分隔端口或范围；dns_records 模式省略"},"scan_profile":{"type":"string","enum":["port_only","service_inventory","vulnerability_scan","dns_records"],"default":"port_only"},"remark":{"type":"string","maxLength":2000,"description":"最多 2000 UTF-8 字节"},"client_reference":{"type":"string","maxLength":200,"description":"最多 200 UTF-8 字节"}}),&[]),
        "ExportInput":object(json!({"query":{"type":"string","maxLength":2048},"fields":reference("Fields"),"format":{"type":"string","enum":["json","jsonl","csv"],"default":"json"},"start_at":reference("InputTime"),"end_at":reference("InputTime")}),&[]),
        "ReportInput":object(json!({"start_at":reference("InputTime"),"end_at":reference("InputTime"),"format":{"type":"string","enum":["json","jsonl","csv"],"default":"json"}}),&["start_at","end_at"]),
        "StatisticsInput":object(json!({"data_type":{"type":"string","enum":["discovery","port","service","tasks","scanners"],"default":"discovery"},"group_by":{"type":"string","enum":["day","week","month","scanner","task_source","port","service"]},"metrics":strings(20),"start_at":reference("InputTime"),"end_at":reference("InputTime"),"timezone":{"type":"string","description":"必须等于服务业务时区；从统计目录获取"},"comparison":{"type":"string","enum":["previous"]}}),&[]),
        "StatisticsDetailsInput":object(json!({"data_type":{"type":"string","enum":["discovery","port","service","tasks","scanners"]},"group_by":{"type":"string"},"start_at":reference("InputTime"),"end_at":reference("InputTime"),"timezone":{"type":"string"},"category":{"type":"string","description":"仅支持 port/service 明细"},"page_size":page,"cursor":cursor}),&[]),
        "WebhookInput":object(json!({"url":{"type":"string","format":"uri","description":"管理员批准的明确域名，HTTPS 443，无用户信息、片段和重定向"},"event_types":{"type":"array","minItems":1,"items":{"type":"string","enum":model::EVENT_TYPES}},"enabled":{"type":"boolean","default":true}}),&["url","event_types"]),
        "SavedSearchInput":object(json!({"name":{"type":"string","minLength":1,"maxLength":100},"query":{"type":"string","minLength":1,"maxLength":2048},"expected_revision":{"type":"integer","format":"int64","description":"仅 PATCH 必填"}}),&["name","query"]),
        "Job":{"type":"object","properties":{"id":{"type":"string","format":"uuid"},"kind":{"type":"string","enum":["export","report"]},"status":{"type":"string","enum":["queued","running","succeeded","failed","cancelled","deleted"]},"policy_revision":{"type":"integer","format":"int64"},"last_error":{"type":["string","null"]},"created_at":{"type":"string","format":"date-time"},"expires_at":{"type":"string","format":"date-time"}}}
    })
}
pub(super) fn additional_scopes(e: &Endpoint) -> &'static [&'static str] {
    if e.path.starts_with("/exports") {
        &["assets:read"]
    } else if e.path.starts_with("/reports") {
        &["analytics:read"]
    } else if matches!(e.path, "/assets/{ip}/refresh" | "/tasks/{task_id}/retry") {
        &["tasks:create"]
    } else {
        &[]
    }
}
pub(super) fn operation(e: &Endpoint) -> Value {
    let mut parameters = e
        .path
        .split('/')
        .filter(|s| s.starts_with('{'))
        .map(|s| {
            let name = s.trim_matches(['{', '}']);
            let schema = if name == "format" {
                json!({"type":"string","enum":["json","jsonl","csv"]})
            } else if name == "port" {
                json!({"type":"integer","minimum":1,"maximum":65535})
            } else if name.ends_with("_id") && name != "finding_id" {
                json!({"type":"string","format":"uuid"})
            } else {
                json!({"type":"string"})
            };
            json!({"name":name,"in":"path","required":true,"schema":schema})
        })
        .collect::<Vec<_>>();
    let request_schema = match (e.method, e.path) {
        ("POST", "/assets/search") => Some(reference("AssetSearch")),
        ("POST", "/assets/search/validate") => Some(object(
            json!({"query":{"type":"string","maxLength":2048}}),
            &["query"],
        )),
        ("POST", "/assets/lookup") => Some(object(
            json!({"ips":{"type":"array","minItems":1,"maxItems":100,"items":{"type":"string"}},"fields":reference("Fields"),"page_size":{"type":"integer","minimum":1,"maximum":100},"cursor":{"type":"string","format":"uuid"}}),
            &["ips"],
        )),
        ("POST", "/domains/lookup") => Some(object(
            json!({"domains":{"type":"array","minItems":1,"maxItems":20,"items":{"type":"string"}}}),
            &["domains"],
        )),
        ("POST", "/vulnerabilities/search" | "/vulnerabilities/summary") => {
            Some(reference("VulnerabilitySearch"))
        }
        ("POST", "/tasks" | "/tasks/validate" | "/tasks/estimate" | "/assets/{ip}/refresh") => {
            Some(reference("TaskInput"))
        }
        ("POST", "/analytics/statistics/details") => Some(reference("StatisticsDetailsInput")),
        ("POST", path) if path.starts_with("/analytics/") => Some(reference("StatisticsInput")),
        ("POST", "/exports") => Some(reference("ExportInput")),
        ("POST", "/reports") => Some(reference("ReportInput")),
        ("POST", "/webhooks") | ("PATCH", "/webhooks/{webhook_id}") => {
            Some(reference("WebhookInput"))
        }
        ("POST", "/saved-searches") | ("PATCH", "/saved-searches/{search_id}") => {
            Some(reference("SavedSearchInput"))
        }
        ("PUT", "/assets/{ip}/annotations/{key}") => Some(object(
            json!({"value":{"type":"string","minLength":1,"maxLength":2048}}),
            &["value"],
        )),
        _ => None,
    };
    if e.method == "GET" {
        let schema_name = if e.path == "/tasks" {
            Some("ObservationSearch")
        } else if e.path.contains("vulnerabilities") {
            Some("VulnerabilitySearch")
        } else if e.path.starts_with("/domains/")
            || e.path.ends_with("/observations")
            || e.path.ends_with("/history")
            || e.path.ends_with("/results")
            || e.path.ends_with("/dns-comparison")
        {
            Some("ObservationSearch")
        } else if e.path.starts_with("/assets/") && !e.path.contains("/annotations") {
            Some("AssetSearch")
        } else if e.path == "/analytics/overview" {
            Some("ObservationSearch")
        } else {
            None
        };
        if let Some(name) = schema_name {
            for (name, schema) in schemas()[name]["properties"].as_object().unwrap() {
                if (e.path == "/tasks" || e.path == "/analytics/overview")
                    && matches!(name.as_str(), "task_id" | "execution_id")
                {
                    continue;
                }
                parameters.push(json!({"name":name,"in":"query","schema":schema,"style":"form","explode":false}));
            }
        }
        if e.path == "/events" {
            parameters.extend([json!({"name":"after","in":"query","schema":{"type":"integer","format":"int64","default":0}}),json!({"name":"page_size","in":"query","schema":{"type":"integer","minimum":1,"maximum":100,"default":50}})]);
        }
    }
    let accepted = e.method == "POST"
        && matches!(
            e.path,
            "/tasks" | "/exports" | "/reports" | "/tasks/{task_id}/retry"
        );
    let idempotent = e.method == "POST"
        && matches!(
            e.path,
            "/tasks" | "/exports" | "/reports" | "/tasks/{task_id}/retry" | "/assets/{ip}/refresh"
        );
    if idempotent {
        parameters.push(json!({"name":"Idempotency-Key","in":"header","required":true,"schema":{"type":"string","minLength":1,"maxLength":128},"description":"应用与操作范围内 24 小时有效；重放相同 JSON 对象，不同内容返回 409"}));
    }
    let download = e.path.ends_with("/download") || e.path.ends_with("/artifacts/{format}");
    let success = if download {
        json!({"description":"文件流；Content-Disposition: attachment。文件最多 8 MiB","content":{"application/json":{"schema":{"type":"string","format":"binary"}},"text/csv":{"schema":{"type":"string","format":"binary"}},"application/x-ndjson":{"schema":{"type":"string","format":"binary"}}}})
    } else {
        json!({"description":if accepted{"异步任务已受理，轮询状态或订阅事件"}else{"成功，JSON 数据位于 data"},"content":{"application/json":{"schema":reference("Envelope")}}})
    };
    let mut responses = serde_json::Map::new();
    responses.insert(if accepted { "202" } else { "200" }.into(), success);
    for (code, description) in [
        ("400", "传输或格式错误"),
        ("401", "凭据过期、撤销、应用停用或平台关闭"),
        ("403", "功能、字段、目标或来源未授权"),
        ("404", "资源不存在或不可见"),
        ("409", "版本、策略或幂等冲突"),
        ("413", "请求体超过 128 KiB"),
        ("422", "参数或计算预算无效"),
        ("429", "配额或统计并发耗尽"),
        ("503", "维护或依赖不可用"),
    ] {
        responses.insert(code.into(),json!({"description":description,"content":{"application/json":{"schema":reference("Error")}}}));
    }
    let mut out = json!({"summary":e.summary,"operationId":format!("{}_{}",e.method.to_lowercase(),e.path.trim_matches('/').replace(['/', '{','}'],"_")),"tags":[e.path.trim_start_matches('/').split('/').next().unwrap()],"security":[{"BearerAuth":[]}],"x-required-scope":e.scope,"x-additional-scopes":additional_scopes(e),"parameters":parameters,"responses":responses});
    if let Some(schema) = request_schema {
        out["requestBody"] =
            json!({"required":true,"content":{"application/json":{"schema":schema}}});
    }
    out
}
