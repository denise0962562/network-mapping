use super::*;
#[test]
fn catalog_is_explicit_and_has_no_user_or_system_operations() {
    assert_eq!(catalog::ENDPOINTS.len(), 80);
    let mut seen = std::collections::HashSet::new();
    for e in catalog::ENDPOINTS {
        assert!(seen.insert((e.method, e.path)));
        assert!(model::SCOPES.contains(&e.scope));
        assert!(!e.path.contains("users"));
        assert!(!e.path.contains("scanner/"));
        assert_eq!(catalog::resolve(e.method, e.path).unwrap().path, e.path);
    }
}

#[test]
fn specification_matches_dispatch_and_documents_mutations_and_downloads() {
    let spec = openapi_document();
    let mut operations = std::collections::HashSet::new();
    for e in catalog::ENDPOINTS {
        let operation = &spec["paths"][e.path][e.method.to_lowercase()];
        assert_eq!(operation["x-required-scope"], e.scope);
        assert!(operations.insert(operation["operationId"].as_str().unwrap()));
        if matches!(e.path, "/tasks" | "/exports" | "/reports") && e.method == "POST" {
            assert!(operation["requestBody"].is_object());
            assert!(operation["responses"]["202"].is_object());
            assert!(
                operation["parameters"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|v| v["name"] == "Idempotency-Key" && v["required"] == true)
            );
        }
    }
    assert_eq!(operations.len(), 80);
    assert!(spec["paths"]["/exports/{export_id}/download"]["get"]["responses"]["200"]["content"]["text/csv"].is_object());
    let saved: Value =
        serde_json::from_str(include_str!("../../docs/open-api/openapi.json")).unwrap();
    assert_eq!(
        saved, spec,
        "regenerate with cargo run --example export_openapi"
    );
}

#[actix_web::test]
async fn external_error_middleware_retains_step_up_and_hides_diagnostics() {
    let app=http_test::init_service(App::new().wrap(crate::api_response::ApiErrorMiddleware)
        .route("/api/open-platform/test",web::get().to(||async{HttpResponse::Forbidden().json(json!({"error":{"code":"step_up_required","message":"重新验证"},"diagnostic":"private"}))}))
        .route("/open-api/v1/test",web::get().to(||async{HttpResponse::ServiceUnavailable().json(json!({"error":{"code":"dependency_unavailable","message":"SQL secret trace"}}))}))).await;
    let value: Value = http_test::call_and_read_body_json(
        &app,
        http_test::TestRequest::get()
            .uri("/api/open-platform/test")
            .to_request(),
    )
    .await;
    assert_eq!(value["error"]["code"], "step_up_required");
    assert!(value.get("diagnostic").is_none());
    let value: Value = http_test::call_and_read_body_json(
        &app,
        http_test::TestRequest::get()
            .uri("/open-api/v1/test")
            .to_request(),
    )
    .await;
    assert_eq!(value["error"]["code"], "dependency_unavailable");
    assert!(!value.to_string().contains("SQL"));
}

use actix_web::{App, HttpMessage, HttpServer, dev::Service, test as http_test};
use chrono::{Duration, Utc};
use std::sync::{Arc, Mutex};

fn principal() -> Principal {
    let policy = Policy {
        scopes: model::SCOPES.iter().map(|s| s.to_string()).collect(),
        fields: model::FIELDS.iter().map(|s| s.to_string()).collect(),
        cidrs: vec!["192.0.2.0/24".into(), "2001:db8::/120".into()],
        domains: vec!["example.com".into()],
        tag_ids: vec![7],
        ..Policy::default()
    };
    Principal {
        client_pk: 1,
        client_id: Uuid::new_v4(),
        credential_id: Uuid::new_v4(),
        owner_id: 1,
        name: "test".into(),
        environment: "production".into(),
        revision: 1,
        scopes: policy.scopes.clone(),
        policy,
        expires_at: Utc::now() + Duration::days(1),
    }
}

#[test]
fn scopes_fields_and_tag_projection_are_intersections() {
    let mut p = principal();
    p.scopes.retain(|s| s != "vulnerabilities:evidence");
    assert!(!p.has("vulnerabilities:evidence"));
    let source = json!({"ip":"192.0.2.1","port":443,"password":"secret","http_body":"secret","scanner_id":"secret","tags":[{"id":7,"name":"approved"},{"id":8,"name":"private"}]});
    let out = p.project_endpoint(&source, None);
    assert_eq!(out["tags"].as_array().unwrap().len(), 1);
    for key in ["password", "http_body", "scanner_id"] {
        assert!(out.get(key).is_none());
    }
    p.scopes.retain(|s| s != "tags:read");
    assert!(p.project_endpoint(&source, None).get("tags").is_none());
    assert_eq!(
        p.project_endpoint(&source, Some(&vec!["port".into()])),
        json!({"port":443})
    );
    p.policy.data_mode = "owner".into();
    assert_eq!(p.scope(), ("user", 1));
    p.policy.data_mode = "application".into();
    assert_eq!(p.scope(), ("api_client", 1));
}

#[test]
fn scan_targets_obey_network_exclusions_and_limits() {
    let mut p = principal();
    p.policy.excluded_cidrs = vec!["192.0.2.128/25".into()];
    assert!(tasks::plan(&json!({"targets":["192.0.2.0/24"]}), &p).is_err());
    assert!(tasks::plan(&json!({"targets":["192.0.3.1"]}), &p).is_err());
    assert!(tasks::plan(&json!({"targets":["192.0.2.1","2001:db8::1"]}), &p).is_err());
    for ports in ["0", "443-80", "1-65535", "abc"] {
        assert!(tasks::plan(&json!({"targets":["192.0.2.1"],"ports":ports}), &p).is_err());
    }
    let plan = tasks::plan(
        &json!({"targets":["192.0.2.1","192.0.2.1"],"ports":"443,80,80"}),
        &p,
    )
    .unwrap();
    assert_eq!((plan.target_count, plan.port_count), (1, 2));
    assert!(
        tasks::plan(
            &json!({"domains":["evil-example.com"],"scan_profile":"dns_records"}),
            &p
        )
        .is_err()
    );
    assert!(
        tasks::plan(
            &json!({"domains":["API.EXAMPLE.COM."],"scan_profile":"dns_records"}),
            &p
        )
        .is_ok()
    );
    assert!(tasks::plan(&json!({"targets":["192.0.2.1"],"user_id":2}), &p).is_err());
    assert!(tasks::plan(&json!({"targets":["192.0.2.1"],"ports":443}), &p).is_err());
    p.policy.cidrs.clear();
    assert!(p.policy.allows_ip("192.0.3.1".parse().unwrap()));
    assert!(tasks::plan(&json!({"targets":["192.0.3.1"]}), &p).is_err());
}

#[test]
fn query_cannot_search_unapproved_fields_and_times_are_explicit() {
    let mut p = principal();
    p.policy.fields = vec!["ip".into(), "port".into()];
    assert!(query::compile("ip IN 192.0.2.0/24 AND port = 443", &p).is_ok());
    assert!(query::compile("title = \"secret\"", &p).is_err());
    assert!(query::compile("scanner_id = \"secret\"", &p).is_err());
    assert!(serde_json::from_value::<query::Search>(json!({"user_id":2})).is_err());
    let s: query::Search = serde_json::from_value(
        json!({"start_at":"2026-10-01T08:00:00+08:00","end_at":"2026-10-02T00:00:00Z"}),
    )
    .unwrap();
    assert_eq!(s.start_at, Some(1790812800000));
    assert!(s.validate(&p).is_ok());
    assert!(query::instant(&json!("2026-10-01 12:00")).is_err());
    assert!(model::normalize_domain("evil/example.com").is_err());
    assert!(!p.policy.allows_domain("evilexample.com"));
}

#[test]
fn webhook_destinations_and_export_cells_are_bounded() {
    let allowed = vec!["hooks.example.com".into()];
    assert!(resources::validate_webhook_url("https://hooks.example.com/events", &allowed).is_ok());
    for url in [
        "http://hooks.example.com/events",
        "https://hooks.example.com:8443/",
        "https://evil.hooks.example.com/",
        "https://user:pass@hooks.example.com/",
        "https://127.0.0.1/",
    ] {
        assert!(resources::validate_webhook_url(url, &allowed).is_err());
    }
    for ip in [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "192.0.2.1",
        "::1",
        "::ffff:127.0.0.1",
        "2001:db8::1",
    ] {
        assert!(!resources::public_ip(ip.parse().unwrap()), "{ip}");
    }
    assert!(resources::public_ip("8.8.8.8".parse().unwrap()));
    assert!(worker::csv_cell(&json!(" =SUM(A1)")).starts_with("\"'"));
    assert_eq!(worker::csv_cell(&json!("a\"b")), "\"a\"\"b\"");
    let (bytes, _) =
        worker::render_artifact(&json!({"items":[{"title":"@cmd","ip":"192.0.2.1"}]}), "csv")
            .unwrap();
    assert!(String::from_utf8(bytes).unwrap().contains("'@cmd"));
}

async fn database() -> (Pool, String) {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::ERROR)
        .try_init();
    let mut cfg: tokio_postgres::Config = std::env::var("OPEN_API_TEST_DATABASE_URL")
        .expect("disposable PostgreSQL URL")
        .parse()
        .unwrap();
    let schema = format!("open_api_test_{}", Uuid::new_v4().simple());
    cfg.options(format!("-c search_path={schema}"));
    let pool = Pool::builder(deadpool_postgres::Manager::new(cfg, tokio_postgres::NoTls))
        .max_size(32)
        .build()
        .unwrap();
    let c = pool.get().await.unwrap();
    c.batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    c.batch_execute(include_str!("../../source/database/init.sql"))
        .await
        .unwrap();
    for _ in 0..2 {
        c.batch_execute(include_str!("../../source/database/migrate_open_api.sql"))
            .await
            .unwrap();
    }
    c.batch_execute("INSERT INTO users(id,username,password,role) VALUES(1,'admin','unused',1),(2,'developer','unused',2),(3,'other','unused',2); UPDATE api_platform_settings SET document=document||'{\"enabled\":true}'::JSONB;").await.unwrap();
    let hash = crate::identity::generate_hash_password(
        "fixture-password",
        crate::config::PasswordHashConfig { m: 1, t: 1, p: 1 },
    )
    .unwrap();
    c.execute("UPDATE users SET password=$1 WHERE id IN (1,2)", &[&hash])
        .await
        .unwrap();
    (pool, schema)
}
async fn cleanup(pool: Pool, schema: String) {
    pool.get()
        .await
        .unwrap()
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
    pool.close();
}
async fn seed_client(pool: &Pool, owner: i32) -> (Principal, String) {
    let mut p = principal();
    p.owner_id = owner;
    let c = pool.get().await.unwrap();
    p.client_pk=c.query_one("INSERT INTO api_client(client_id,owner_user_id,name,kind,environment,status,policy,requested_policy) VALUES($1,$2,'fixture','personal','production','active',$3,$3) RETURNING id",&[&p.client_id,&owner,&json!(p.policy)]).await.unwrap().get(0);
    let token = auth::generate_key(p.credential_id).unwrap();
    c.execute("INSERT INTO api_credential(id,client_id,name,secret_hash,scopes,expires_at) VALUES($1,$2,'key',$3,$4,$5)",&[&p.credential_id,&p.client_pk,&model::fingerprint(token.as_bytes()),&p.scopes,&p.expires_at]).await.unwrap();
    (p, token)
}

#[actix_web::test]
#[ignore = "requires disposable OPEN_API_TEST_DATABASE_URL"]
async fn credentials_fail_closed_and_quotas_are_atomic_across_connections() {
    let (pool, schema) = database().await;
    let (p, token) = seed_client(&pool, 2).await;
    let request = http_test::TestRequest::get()
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_http_request();
    assert_eq!(
        auth::authenticate(&request, &pool).await.unwrap().owner_id,
        2
    );
    let cookie_only = http_test::TestRequest::get()
        .cookie(actix_web::cookie::Cookie::new("session", token.clone()))
        .to_http_request();
    assert_eq!(
        auth::authenticate(&cookie_only, &pool)
            .await
            .unwrap_err()
            .status,
        StatusCode::UNAUTHORIZED
    );
    let calls = (0..32).map(|_| {
        let pool = pool.clone();
        async move {
            auth::consume(
                &pool.get().await.unwrap(),
                p.client_pk,
                "parallel",
                7,
                1,
                false,
            )
            .await
        }
    });
    let outcomes = futures::future::join_all(calls).await;
    assert_eq!(outcomes.iter().filter(|r| r.is_ok()).count(), 7);
    assert_eq!(
        outcomes
            .iter()
            .filter(|r| r
                .as_ref()
                .is_err_and(|e| e.status == StatusCode::TOO_MANY_REQUESTS))
            .count(),
        25
    );
    for sql in [
        "UPDATE api_client SET status='paused'",
        "UPDATE users SET disabled_at=NOW() WHERE id=2",
        "UPDATE api_platform_settings SET document=document||'{\"enabled\":false}'::JSONB",
        "UPDATE api_credential SET revoked_at=NOW()",
    ] {
        pool.get().await.unwrap().batch_execute(sql).await.unwrap();
        assert_eq!(
            auth::authenticate(&request, &pool)
                .await
                .unwrap_err()
                .status,
            StatusCode::UNAUTHORIZED
        );
        pool.get().await.unwrap().batch_execute("UPDATE api_client SET status='active'; UPDATE users SET disabled_at=NULL; UPDATE api_platform_settings SET document=document||'{\"enabled\":true}'::JSONB; UPDATE api_credential SET revoked_at=NULL;").await.unwrap();
    }
    let mut c = pool.get().await.unwrap();
    let tx = c.transaction().await.unwrap();
    let metadata = json!({"open_api":{"client_id":p.client_pk,"credential_id":p.credential_id,"policy_revision":p.revision}});
    let current = tasks::follow_up_scope(&tx, &metadata)
        .await
        .unwrap()
        .unwrap();
    auth::consume(
        &tx,
        p.client_pk,
        "tasks.day",
        p.policy.tasks_per_day,
        p.policy.tasks_per_day,
        true,
    )
    .await
    .unwrap();
    assert!(!tasks::reserve_follow_up(&tx, &current, 1).await.unwrap());
    assert_eq!(
        tx.query_one(
            "SELECT COUNT(*) FROM api_usage_bucket WHERE client_id=$1 AND category='tasks.minute'",
            &[&p.client_pk]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    tx.execute(
        "DELETE FROM api_usage_bucket WHERE client_id=$1 AND category='tasks.day'",
        &[&p.client_pk],
    )
    .await
    .unwrap();
    assert!(!tasks::reserve_follow_up(&tx, &current, 6).await.unwrap());
    assert!(tasks::reserve_follow_up(&tx, &current, 1).await.unwrap());
    tx.commit().await.unwrap();
    drop(c);
    cleanup(pool, schema).await;
}

#[actix_web::test]
#[ignore = "requires disposable OPEN_API_TEST_DATABASE_URL"]
async fn task_creation_replay_isolation_and_revocation_gate() {
    let (pool, schema) = database().await;
    let (p, _) = seed_client(&pool, 2).await;
    let (other, _) = seed_client(&pool, 3).await;
    let req = http_test::TestRequest::post()
        .insert_header(("Idempotency-Key", "task-test-1"))
        .to_http_request();
    let input = json!({"targets":["192.0.2.1"],"ports":"443"});
    let task = tasks::create(&req, &pool, &p, &input, None).await.unwrap();
    assert_eq!(
        task,
        tasks::create(&req, &pool, &p, &input, None).await.unwrap()
    );
    assert_eq!(
        tasks::create(
            &req,
            &pool,
            &p,
            &json!({"targets":["192.0.2.2"],"ports":"443"}),
            None
        )
        .await
        .unwrap_err()
        .code,
        "idempotency_conflict"
    );
    let id = task["task_id"].as_str().unwrap();
    let c = pool.get().await.unwrap();
    assert!(tasks::get(&c, &other, id, false).await.is_err());
    assert!(
        c.query_one(
            "SELECT api_scan_task_enabled(t) FROM scan_task t WHERE task_id=$1",
            &[&id]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    c.execute(
        "UPDATE api_credential SET revoked_at=NOW() WHERE id=$1",
        &[&p.credential_id],
    )
    .await
    .unwrap();
    assert!(
        !c.query_one(
            "SELECT api_scan_task_enabled(t) FROM scan_task t WHERE task_id=$1",
            &[&id]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    drop(c);
    worker::reconcile_events(&pool).await.unwrap();
    let c = pool.get().await.unwrap();
    assert_eq!(
        c.query_one("SELECT task_status FROM scan_task WHERE task_id=$1", &[&id])
            .await
            .unwrap()
            .get::<_, String>(0),
        "cancelled"
    );
    c.execute("UPDATE scan_task SET task_end_time=(EXTRACT(EPOCH FROM (NOW()-INTERVAL '31 days'))*1000)::BIGINT WHERE task_id=$1",&[&id]).await.unwrap();
    c.execute(
        "DELETE FROM api_event_outbox WHERE client_id=$1",
        &[&p.client_pk],
    )
    .await
    .unwrap();
    drop(c);
    worker::reconcile_events(&pool).await.unwrap();
    assert_eq!(
        pool.get()
            .await
            .unwrap()
            .query_one(
                "SELECT COUNT(*) FROM api_event_outbox WHERE client_id=$1",
                &[&p.client_pk]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0,
        "retention must not resurrect historical terminal events"
    );
    cleanup(pool, schema).await;
}

#[actix_web::test]
#[ignore = "requires disposable OPEN_API_TEST_DATABASE_URL"]
async fn console_approval_key_and_metadata_version_lifecycle() {
    let (pool, schema) = database().await;
    // Session extensions are supplied by the production authentication middleware.
    // This fixture exercises console authorization without creating real sessions.
    let es = crate::elasticsearch::ElasticsearchService::new(
        crate::config::ElasticsearchConfig::default(),
    )
    .unwrap();
    let app = http_test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(es))
            .wrap_fn(|req, srv| {
                let id = req
                    .headers()
                    .get("X-Test-User")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(2);
                req.extensions_mut().insert(crate::admin::UserBaseI {
                    id,
                    username: if id == 1 {
                        "admin".into()
                    } else {
                        "developer".into()
                    },
                    role: if id == 1 { 1 } else { 2 },
                    email: None,
                    limit_login: false,
                    enable_2fa: false,
                });
                req.extensions_mut().insert(crate::admin::UserSession {
                    session: format!("test-session-{id}"),
                });
                srv.call(req)
            })
            .wrap(crate::api_response::ApiErrorMiddleware)
            .configure(configure),
    )
    .await;
    let policy = principal().policy;
    let request = http_test::TestRequest::post()
        .uri("/api/open-platform/apps")
        .set_json(json!({"name":"integration","purpose":"approved inventory","policy":policy}))
        .to_request();
    let created: Value = http_test::call_and_read_body_json(&app, request).await;
    let id = created["data"]["id"].as_str().unwrap();
    let request = http_test::TestRequest::get()
        .uri(&format!("/api/open-platform/apps/{id}"))
        .insert_header(("X-Test-User", "3"))
        .to_request();
    assert_eq!(
        http_test::call_service(&app, request).await.status(),
        StatusCode::NOT_FOUND
    );
    let request = http_test::TestRequest::post()
        .uri(&format!("/api/open-platform/apps/{id}/credentials"))
        .set_json(json!({"name":"pending"}))
        .to_request();
    let blocked: Value = http_test::call_and_read_body_json(&app, request).await;
    assert_eq!(blocked["error"]["code"], "step_up_required");
    let request = http_test::TestRequest::post()
        .uri("/api/open-platform/step-up")
        .set_json(json!({"password":"wrong"}))
        .to_request();
    let response = http_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let error: Value = http_test::read_body_json(response).await;
    assert_eq!(error["error"]["code"], "verification_failed");
    for user in [1, 2] {
        let request = http_test::TestRequest::post()
            .uri("/api/open-platform/step-up")
            .insert_header(("X-Test-User", user.to_string()))
            .set_json(json!({"password":"fixture-password"}))
            .to_request();
        assert_eq!(
            http_test::call_service(&app, request).await.status(),
            StatusCode::OK
        );
    }
    let c = pool.get().await.unwrap();
    let approval: Uuid = c
        .query_one("SELECT id FROM api_approval_request", &[])
        .await
        .unwrap()
        .get(0);
    drop(c);
    let request = http_test::TestRequest::post()
        .uri(&format!("/api/open-platform/approvals/{approval}/review"))
        .set_json(json!({"approved":true}))
        .to_request();
    assert_eq!(
        http_test::call_service(&app, request).await.status(),
        StatusCode::FORBIDDEN
    );
    let request = http_test::TestRequest::post()
        .uri(&format!("/api/open-platform/approvals/{approval}/review"))
        .insert_header(("X-Test-User", "1"))
        .set_json(json!({"approved":true}))
        .to_request();
    let approved: Value = http_test::call_and_read_body_json(&app, request).await;
    assert!(approved.get("error").is_none(), "{approved}");
    let request = http_test::TestRequest::get()
        .uri(&format!("/api/open-platform/apps/{id}"))
        .to_request();
    let before: Value = http_test::call_and_read_body_json(&app, request).await;
    let request = http_test::TestRequest::patch()
        .uri(&format!("/api/open-platform/apps/{id}"))
        .set_json(
            json!({"name":"renamed","expected_revision":before["data"]["application"]["revision"]}),
        )
        .to_request();
    let renamed: Value = http_test::call_and_read_body_json(&app, request).await;
    assert_eq!(
        renamed["data"]["policy_revision"],
        before["data"]["application"]["policy_revision"]
    );
    assert_ne!(
        renamed["data"]["revision"],
        before["data"]["application"]["revision"]
    );
    let request = http_test::TestRequest::post()
        .uri(&format!("/api/open-platform/apps/{id}/credentials"))
        .set_json(json!({"name":"key","scopes":["metadata:read"],"expires_days":30}))
        .to_request();
    let issued: Value = http_test::call_and_read_body_json(&app, request).await;
    let token = issued["data"]["token"].as_str().unwrap();
    let key = auth::key_id(token).unwrap();
    let request = http_test::TestRequest::get()
        .uri("/open-api/v1/me")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    assert_eq!(
        http_test::call_service(&app, request).await.status(),
        StatusCode::OK
    );
    let request = http_test::TestRequest::get()
        .uri(&format!("/api/open-platform/apps/{id}"))
        .to_request();
    let listed = http_test::call_and_read_body(&app, request).await;
    assert!(!String::from_utf8_lossy(&listed).contains(token));
    let request = http_test::TestRequest::post()
        .uri(&format!(
            "/api/open-platform/apps/{id}/credentials/{key}/revoke"
        ))
        .set_json(json!({}))
        .to_request();
    assert_eq!(
        http_test::call_service(&app, request).await.status(),
        StatusCode::OK
    );
    let request = http_test::TestRequest::get()
        .uri("/open-api/v1/me")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    assert_eq!(
        http_test::call_service(&app, request).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let request = http_test::TestRequest::post()
        .uri(&format!("/api/open-platform/apps/{id}/invoke"))
        .set_json(json!({"credential_id":key,"method":"GET","path":"/me","payload":{}}))
        .to_request();
    assert_eq!(
        http_test::call_service(&app, request).await.status(),
        StatusCode::FORBIDDEN,
        "revoked API keys must not trigger Web session expiry"
    );
    cleanup(pool, schema).await;
}

#[derive(Default)]
struct SearchFixture {
    body: Value,
    queries: Vec<Value>,
}
async fn fixture_search(
    data: web::Data<Arc<Mutex<SearchFixture>>>,
    body: web::Json<Value>,
) -> HttpResponse {
    let mut fixture = data.lock().unwrap();
    fixture.queries.push(body.into_inner());
    HttpResponse::Ok().json(fixture.body.clone())
}

#[actix_web::test]
#[ignore = "requires disposable OPEN_API_TEST_DATABASE_URL and local HTTP sockets"]
async fn scoped_queries_cursors_dns_and_export_worker() {
    let (pool, schema) = database().await;
    let (p, token) = seed_client(&pool, 2).await;
    let fixture = Arc::new(Mutex::new(SearchFixture::default()));
    let shared = fixture.clone();
    let server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(shared.clone()))
            .default_service(web::to(fixture_search))
    })
    .bind(("127.0.0.1", 0))
    .unwrap();
    let addr = server.addrs()[0];
    let server = server.run();
    let handle = server.handle();
    tokio::spawn(server);
    let es = crate::elasticsearch::ElasticsearchService::new(crate::config::ElasticsearchConfig {
        url: format!("http://{addr}"),
        ..Default::default()
    })
    .unwrap();
    es.open_api_test_ready();
    fixture.lock().unwrap().body = json!({"hits":{"hits":[{"_source":{"ip":"192.0.2.1","port":443,"password":"private","tags":[{"id":7},{"id":8}]},"sort":[1]},{"_source":{"ip":"192.0.2.2","port":80},"sort":[2]}]},"_shards":{"failed":0}});
    let s = query::Search {
        page_size: Some(1),
        ..Default::default()
    };
    let result = query::endpoints(&pool, &es, &p, &s, vec![]).await.unwrap();
    assert!(result["items"][0].get("password").is_none());
    assert_eq!(result["items"][0]["tags"].as_array().unwrap().len(), 1);
    let sent = fixture.lock().unwrap().queries[0].to_string();
    assert!(sent.contains("api_client"));
    assert!(sent.contains("192.0.2.0/24"));
    let cursor: Uuid = result["next_cursor"].as_str().unwrap().parse().unwrap();
    let mut wrong = s.clone();
    wrong.cursor = Some(cursor);
    wrong.query = Some("port = 80".into());
    assert!(
        query::endpoints(&pool, &es, &p, &wrong, vec![])
            .await
            .is_err()
    );
    let mut wrong_p = p.clone();
    wrong_p.credential_id = Uuid::new_v4();
    assert!(
        query::endpoints(
            &pool,
            &es,
            &wrong_p,
            &query::Search {
                cursor: Some(cursor),
                ..s.clone()
            },
            vec![]
        )
        .await
        .is_err()
    );
    fixture.lock().unwrap().body = json!({"hits":{"hits":[{"_source":{"dns":{"question":{"name":"api.example.com"},"answers":[{"type":"A","value":"192.0.2.1"},{"type":"A","value":"10.0.0.1"}]},"resolver":{"id":"one","ip":"private"}},"sort":[1]}]},"_shards":{"failed":0}});
    let dns = query::dns(&pool, &es, &p, Some("api.example.com"), &Default::default())
        .await
        .unwrap();
    assert_eq!(
        dns["items"][0]["dns"]["answers"].as_array().unwrap().len(),
        1
    );
    assert!(dns["items"][0].get("resolver").is_none());
    fixture.lock().unwrap().body = json!({"hits":{"hits":[{"_source":{"ip":"192.0.2.1","port":443,"password":"private"},"sort":[1]}]},"_shards":{"failed":0}});
    let app = http_test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(es.clone()))
            .wrap(crate::middlewares::csrfmiddleware::CsrfMiddleware)
            .wrap(crate::api_response::ApiErrorMiddleware)
            .configure(configure),
    )
    .await;
    let request = http_test::TestRequest::post()
        .uri("/open-api/v1/exports")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Idempotency-Key", "export-1"))
        .set_json(json!({"format":"csv","fields":["ip","port"]}))
        .to_request();
    let response = http_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let created: Value = http_test::read_body_json(response).await;
    let id = created["data"]["id"].as_str().unwrap();
    worker::process_job(&pool, &es).await.unwrap();
    let c = pool.get().await.unwrap();
    let row = c
        .query_one(
            "SELECT status,artifact,artifact_checksum FROM api_job WHERE id=$1",
            &[&Uuid::parse_str(id).unwrap()],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "succeeded");
    let bytes: Vec<u8> = row.get(1);
    assert_eq!(row.get::<_, String>(2), model::fingerprint(&bytes));
    assert!(!String::from_utf8_lossy(&bytes).contains("private"));
    drop(c);
    let request = http_test::TestRequest::get()
        .uri(&format!("/open-api/v1/exports/{id}/download"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let response = http_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("Content-Disposition").is_some());
    pool.get()
        .await
        .unwrap()
        .execute(
            "UPDATE api_client SET revision=revision+1 WHERE id=$1",
            &[&p.client_pk],
        )
        .await
        .unwrap();
    let request = http_test::TestRequest::get()
        .uri(&format!("/open-api/v1/exports/{id}/download"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    assert_eq!(
        http_test::call_service(&app, request).await.status(),
        StatusCode::FORBIDDEN
    );
    let request = http_test::TestRequest::get()
        .uri("/open-api/v1/events")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let events: Value = http_test::call_and_read_body_json(&app, request).await;
    assert_eq!(events["data"]["items"], json!([]));
    assert!(events["data"]["next_after"].as_i64().is_some_and(|n| n > 0));
    fixture.lock().unwrap().body =
        json!({"_shards":{"failed":0},"aggregations":{"groups":{"buckets":[]}}});
    let request=http_test::TestRequest::post().uri("/open-api/v1/reports").insert_header(("Authorization",format!("Bearer {token}"))).insert_header(("Idempotency-Key","report-1")).set_json(json!({"start_at":"2026-10-01T00:00:00Z","end_at":"2026-10-08T00:00:00Z","format":"json"})).to_request();
    let response = http_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let report: Value = http_test::read_body_json(response).await;
    let report_id = report["data"]["id"].as_str().unwrap();
    worker::process_job(&pool, &es).await.unwrap();
    let request = http_test::TestRequest::get()
        .uri(&format!("/open-api/v1/reports/{report_id}/data"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let report: Value = http_test::call_and_read_body_json(&app, request).await;
    assert_eq!(
        report["data"]["payload"]["quality"]["scope"],
        "authorized_successful_executions"
    );
    assert!(report["data"]["artifact_checksum"].as_str().is_some());
    handle.stop(true).await;
    cleanup(pool, schema).await;
}
