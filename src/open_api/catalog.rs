use serde::Serialize;
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct Endpoint {
    pub method: &'static str,
    pub path: &'static str,
    pub scope: &'static str,
    pub summary: &'static str,
}
macro_rules! endpoints {($(($method:literal,$path:literal,$scope:literal,$summary:literal)),*$(,)?)=>{pub const ENDPOINTS:&[Endpoint]=&[$(Endpoint{method:$method,path:$path,scope:$scope,summary:$summary}),*];};}
endpoints![
    (
        "GET",
        "/capabilities",
        "metadata:read",
        "当前凭据可用的接口"
    ),
    ("GET", "/me", "metadata:read", "当前应用身份"),
    ("GET", "/me/scopes", "metadata:read", "有效权限和字段"),
    ("GET", "/me/quotas", "metadata:read", "应用配额"),
    ("GET", "/me/usage", "metadata:read", "自身用量"),
    ("GET", "/service-status", "metadata:read", "服务可用状态"),
    ("GET", "/catalog/search-fields", "metadata:read", "搜索字段"),
    (
        "GET",
        "/catalog/scan-profiles",
        "metadata:read",
        "批准的扫描模式"
    ),
    (
        "GET",
        "/catalog/dns-resolvers",
        "metadata:read",
        "批准的解析器目录"
    ),
    ("GET", "/catalog/statistics", "metadata:read", "统计目录"),
    ("POST", "/assets/search", "assets:read", "高级资产搜索"),
    (
        "POST",
        "/assets/search/validate",
        "assets:read",
        "搜索语法校验"
    ),
    ("GET", "/assets/{ip}", "assets:read", "资产摘要"),
    ("POST", "/assets/lookup", "assets:read", "批量资产查询"),
    ("GET", "/assets/{ip}/ports", "assets:read", "当前端口"),
    (
        "GET",
        "/assets/{ip}/ports/{port}/history",
        "observations:read",
        "端口观察历史"
    ),
    ("GET", "/assets/{ip}/services", "assets:read", "服务信息"),
    ("GET", "/assets/{ip}/tls", "assets:read", "TLS 信息"),
    ("GET", "/assets/{ip}/tags", "tags:read", "授权资产标签"),
    (
        "GET",
        "/assets/{ip}/observations",
        "observations:read",
        "资产观察"
    ),
    (
        "POST",
        "/assets/{ip}/refresh",
        "assets:refresh",
        "提交刷新扫描"
    ),
    ("GET", "/domains/{domain}", "dns:read", "域名摘要"),
    (
        "GET",
        "/domains/{domain}/records",
        "dns:read",
        "成功执行中的 DNS 记录"
    ),
    (
        "GET",
        "/domains/{domain}/observations",
        "dns:read",
        "DNS 观察"
    ),
    (
        "GET",
        "/domains/{domain}/addresses",
        "dns:read",
        "域名关联地址"
    ),
    (
        "GET",
        "/domains/{domain}/related-domains",
        "dns:read",
        "观察中的关联域名"
    ),
    ("POST", "/domains/lookup", "dns:read", "批量域名查询"),
    (
        "POST",
        "/vulnerabilities/search",
        "vulnerabilities:read",
        "漏洞观察查询"
    ),
    (
        "GET",
        "/vulnerabilities/{finding_id}",
        "vulnerabilities:read",
        "漏洞观察详情"
    ),
    (
        "GET",
        "/assets/{ip}/vulnerabilities",
        "vulnerabilities:read",
        "资产漏洞观察"
    ),
    (
        "GET",
        "/tasks/{task_id}/vulnerabilities",
        "vulnerabilities:read",
        "任务漏洞观察"
    ),
    (
        "POST",
        "/vulnerabilities/summary",
        "vulnerabilities:read",
        "漏洞观察摘要"
    ),
    ("GET", "/tags", "tags:read", "批准的标签目录"),
    ("GET", "/tag-categories", "tags:read", "批准的标签分类"),
    (
        "GET",
        "/assets/{ip}/annotations",
        "annotations:read",
        "应用私有注释"
    ),
    (
        "PUT",
        "/assets/{ip}/annotations/{key}",
        "annotations:write",
        "保存应用注释"
    ),
    (
        "DELETE",
        "/assets/{ip}/annotations/{key}",
        "annotations:write",
        "删除应用注释"
    ),
    ("GET", "/tasks", "tasks:read", "授权任务列表"),
    ("GET", "/tasks/{task_id}", "tasks:read", "任务详情"),
    (
        "GET",
        "/tasks/{task_id}/executions",
        "tasks:read",
        "执行列表"
    ),
    (
        "GET",
        "/tasks/{task_id}/executions/{execution_id}",
        "tasks:read",
        "执行详情"
    ),
    ("GET", "/tasks/{task_id}/results", "tasks:read", "执行结果"),
    (
        "GET",
        "/tasks/{task_id}/dns-comparison",
        "dns:read",
        "任务 DNS 对比"
    ),
    (
        "GET",
        "/tasks/{task_id}/children",
        "tasks:read",
        "DNS 子任务"
    ),
    (
        "POST",
        "/tasks/validate",
        "tasks:create",
        "校验目标和扫描模式"
    ),
    ("POST", "/tasks/estimate", "tasks:create", "预估扫描工作量"),
    ("POST", "/tasks", "tasks:create", "创建受控扫描"),
    (
        "POST",
        "/tasks/{task_id}/cancel",
        "tasks:cancel",
        "取消应用任务"
    ),
    (
        "POST",
        "/tasks/{task_id}/retry",
        "tasks:retry",
        "重试应用任务"
    ),
    ("GET", "/analytics/overview", "analytics:read", "范围内概览"),
    (
        "POST",
        "/analytics/distribution",
        "analytics:read",
        "端口和服务分布"
    ),
    (
        "POST",
        "/analytics/discovery-series",
        "analytics:read",
        "发现趋势"
    ),
    (
        "POST",
        "/analytics/statistics/query",
        "analytics:read",
        "统计查询"
    ),
    (
        "POST",
        "/analytics/statistics/details",
        "analytics:read",
        "统计明细"
    ),
    ("GET", "/reports", "reports:read", "应用报告列表"),
    ("GET", "/reports/{report_id}", "reports:read", "报告详情"),
    (
        "GET",
        "/reports/{report_id}/data",
        "reports:read",
        "归档报告数据"
    ),
    ("POST", "/reports", "reports:create", "生成范围化报告"),
    (
        "GET",
        "/reports/{report_id}/artifacts/{format}",
        "reports:read",
        "报告文件"
    ),
    ("POST", "/exports", "exports:create", "创建异步导出"),
    ("GET", "/exports", "exports:read", "导出列表"),
    ("GET", "/exports/{export_id}", "exports:read", "导出状态"),
    (
        "POST",
        "/exports/{export_id}/cancel",
        "exports:create",
        "取消导出"
    ),
    (
        "GET",
        "/exports/{export_id}/download",
        "exports:read",
        "读取生成文件"
    ),
    (
        "DELETE",
        "/exports/{export_id}",
        "exports:create",
        "删除生成文件"
    ),
    ("GET", "/events", "events:read", "游标拉取自身事件"),
    ("GET", "/webhooks", "webhooks:manage", "订阅列表"),
    ("POST", "/webhooks", "webhooks:manage", "创建签名订阅"),
    (
        "GET",
        "/webhooks/{webhook_id}",
        "webhooks:manage",
        "订阅详情"
    ),
    (
        "PATCH",
        "/webhooks/{webhook_id}",
        "webhooks:manage",
        "修改订阅"
    ),
    (
        "DELETE",
        "/webhooks/{webhook_id}",
        "webhooks:manage",
        "停用订阅"
    ),
    (
        "POST",
        "/webhooks/{webhook_id}/test",
        "webhooks:manage",
        "测试订阅"
    ),
    (
        "GET",
        "/webhooks/{webhook_id}/deliveries",
        "webhooks:manage",
        "投递列表"
    ),
    (
        "GET",
        "/webhook-deliveries/{delivery_id}",
        "webhooks:manage",
        "投递详情"
    ),
    (
        "POST",
        "/webhook-deliveries/{delivery_id}/retry",
        "webhooks:manage",
        "重试投递"
    ),
    (
        "GET",
        "/saved-searches",
        "saved_searches:manage",
        "保存的查询列表"
    ),
    (
        "POST",
        "/saved-searches",
        "saved_searches:manage",
        "保存查询"
    ),
    (
        "GET",
        "/saved-searches/{search_id}",
        "saved_searches:manage",
        "读取保存的查询"
    ),
    (
        "PATCH",
        "/saved-searches/{search_id}",
        "saved_searches:manage",
        "修改保存的查询"
    ),
    (
        "DELETE",
        "/saved-searches/{search_id}",
        "saved_searches:manage",
        "删除保存的查询"
    ),
];
pub(crate) fn resolve(method: &str, path: &str) -> Option<Endpoint> {
    let segments = path.trim_matches('/').split('/').collect::<Vec<_>>();
    ENDPOINTS
        .iter()
        .find(|e| {
            e.method == method && {
                let template = e.path.trim_matches('/').split('/').collect::<Vec<_>>();
                template.len() == segments.len()
                    && template
                        .iter()
                        .zip(&segments)
                        .all(|(a, b)| !b.is_empty() && (a.starts_with('{') || a == b))
            }
        })
        .copied()
}
pub(crate) fn openapi() -> Value {
    let mut paths = serde_json::Map::new();
    for e in ENDPOINTS {
        paths.entry(e.path).or_insert_with(|| json!({}))[e.method.to_lowercase()] =
            super::contract::operation(e);
    }
    json!({"openapi":"3.1.0","info":{"title":"Network Mapping Open API","version":"1.0.0","description":"外部应用独立鉴权，权限与数据范围取交集；不开放用户和系统管理。完整数据口径与示例见 docs/OPEN_API.md。"},"servers":[{"url":"/open-api/v1"}],"paths":paths,"components":{"securitySchemes":{"BearerAuth":{"type":"http","scheme":"bearer","bearerFormat":"nm_api_<uuid>.<secret>"}},"schemas":super::contract::schemas()}})
}
