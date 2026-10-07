//! Explicitly opt-in tests against an isolated schema in a disposable database.
use super::*;
use actix_web::{App, HttpMessage, dev::Service, test, web};
use deadpool_postgres::{Manager, Pool};

async fn pool() -> (Pool, String) {
    let mut config: tokio_postgres::Config = std::env::var("ANALYTICS_TEST_DATABASE_URL")
        .expect("disposable database")
        .parse()
        .unwrap();
    let schema = format!("statistics_{}", uuid::Uuid::new_v4().simple());
    config.options(format!("-c search_path={schema} -c timezone=UTC"));
    let pool = Pool::builder(Manager::new(config, tokio_postgres::NoTls))
        .max_size(8)
        .build()
        .unwrap();
    let client = pool.get().await.unwrap();
    client
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    client.batch_execute("CREATE TABLE runtime_configuration(namespace TEXT PRIMARY KEY,document JSONB,revision BIGINT DEFAULT 1,schema_version INT DEFAULT 1,updated_at TIMESTAMPTZ,updated_by_user_id INT);
      CREATE TABLE runtime_configuration_revision(namespace TEXT,revision BIGINT,schema_version INT,document JSONB,changed_by_user_id INT,change_reason TEXT,changed_at TIMESTAMPTZ DEFAULT NOW(),PRIMARY KEY(namespace,revision));
      CREATE TABLE scan_task(id INT PRIMARY KEY,task_id TEXT,user_id INT,task_source TEXT,task_create_time BIGINT,task_end_time BIGINT,task_status TEXT);
      CREATE TABLE scan_task_execution(id INT PRIMARY KEY,execution_id TEXT,task_id INT,assigned_scanner_id TEXT,execution_status TEXT,task_start_time BIGINT,task_end_time BIGINT);
      CREATE TABLE scanner_info(scanner_id TEXT,name TEXT);
      CREATE TABLE analytics_discovery_fact(execution_id INT,day_start DATE,first_observed_at TIMESTAMPTZ,owner_id INT,scanner_id TEXT,task_source TEXT,ip_address INET);
      CREATE TABLE analytics_distribution_30m(execution_id INT,bucket_start TIMESTAMPTZ,owner_id INT,scanner_id TEXT,task_source TEXT,dimension TEXT,label TEXT,endpoint_count BIGINT);
      CREATE TABLE analytics_watermark(watermark_key TEXT,data_as_of TIMESTAMPTZ);
      INSERT INTO analytics_watermark VALUES('scan_analysis',NOW());
      INSERT INTO scan_task VALUES(1,'019a0000-0000-7000-8000-000000000001',1,'manual',1788220800000,1788220801000,'succeeded'),(2,'019a0000-0000-7000-8000-000000000002',2,'manual',1788220800000,1788220802000,'failed');
      INSERT INTO scan_task_execution VALUES(1,'execution-a',1,'00000000-0000-4000-8000-000000000001','succeeded',1788220800000,1788220801000),(2,'execution-b',2,'00000000-0000-4000-8000-000000000002','failed',1788220800000,1788220802000);
      INSERT INTO analytics_discovery_fact VALUES(1,'2026-09-01','2026-09-01T00:00:00Z',1,'00000000-0000-4000-8000-000000000001','manual','192.0.2.1'),(1,'2026-09-02','2026-09-02T00:00:00Z',1,'00000000-0000-4000-8000-000000000001','manual','192.0.2.2'),(2,'2026-09-01','2026-09-01T00:00:00Z',2,'00000000-0000-4000-8000-000000000002','manual','192.0.2.99');
      INSERT INTO analytics_distribution_30m VALUES(1,'2026-09-01T00:00:00Z',1,'00000000-0000-4000-8000-000000000001','manual','port','443',2),(2,'2026-09-01T00:00:00Z',2,'00000000-0000-4000-8000-000000000002','manual','port','443',99);").await.unwrap();
    client
        .batch_execute(include_str!("../../source/database/migrate_statistics.sql"))
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO runtime_configuration(namespace,document) VALUES($1,$2)",
            &[&NAMESPACE, &json!(CacheConfig::default())],
        )
        .await
        .unwrap();
    drop(client);
    (pool, schema)
}
async fn cleanup(pool: &Pool, schema: &str) {
    pool.get()
        .await
        .unwrap()
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires disposable ANALYTICS_TEST_DATABASE_URL"]
async fn statistics_cluster_slots_and_persisted_cache_revision() {
    let (pool, schema) = pool().await;
    let first = ClusterSlot::acquire(&pool).await.unwrap();
    let second = ClusterSlot::acquire(&pool).await.unwrap();
    assert!(ClusterSlot::acquire(&pool).await.is_err());
    first.release().await.unwrap();
    ClusterSlot::acquire(&pool)
        .await
        .unwrap()
        .release()
        .await
        .unwrap();
    drop(second);
    // A dropped slot closes its connection. PostgreSQL observes the disconnect asynchronously.
    tokio::time::sleep(Duration::from_millis(30)).await;
    ClusterSlot::acquire(&pool)
        .await
        .unwrap()
        .release()
        .await
        .unwrap();
    let a = StatisticsService::new();
    let b = StatisticsService::new();
    a.refresh(&pool).await.unwrap();
    b.refresh(&pool).await.unwrap();
    for service in [&a, &b] {
        service
            .execute("key".into(), 1, "realtime".into(), |_| async {
                Ok(json!(1))
            })
            .await
            .unwrap();
    }
    let config = CacheConfig {
        enabled: false,
        ..Default::default()
    };
    let revision = crate::runtime_config::persist(&pool, NAMESPACE, 1, &config, "disable cache", 1)
        .await
        .unwrap();
    assert_eq!(revision, 2);
    assert!(matches!(
        crate::runtime_config::persist(&pool, NAMESPACE, 1, &config, "stale", 1).await,
        Err(crate::runtime_config::PersistError::Conflict)
    ));
    a.refresh(&pool).await.unwrap();
    b.refresh(&pool).await.unwrap();
    assert_eq!(a.status()["entries"], 0);
    assert_eq!(b.status()["enabled"], false);
    b.publish_status(&pool).await.unwrap();
    assert_eq!(
        pool.get()
            .await
            .unwrap()
            .query_one("SELECT COUNT(*) FROM statistics_instance", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    cleanup(&pool, &schema).await;
}

#[actix_web::test]
#[ignore = "requires disposable ANALYTICS_TEST_DATABASE_URL"]
async fn statistics_http_scope_comparison_percentiles_and_cursor_pagination() {
    let (pool, schema) = pool().await;
    let service = StatisticsService::new();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(service))
            .app_data(web::Data::new(
                crate::elasticsearch::ElasticsearchService::new(Default::default()).unwrap(),
            ))
            .app_data(web::Data::new(crate::runtime_config::RuntimeConfig::new(
                crate::config::AnalyticsSnapshotConfig {
                    mode: crate::config::AnalyticsSnapshotMode::Snapshot,
                    ..Default::default()
                },
                1,
            )))
            .wrap_fn(|req, srv| {
                req.extensions_mut().insert(crate::admin::UserBaseI {
                    id: 1,
                    role: 2,
                    username: "ordinary".into(),
                    email: None,
                    limit_login: false,
                    enable_2fa: false,
                });
                srv.call(req)
            })
            .service(crate::handlers::statistics::query)
            .service(crate::handlers::statistics::cache_status)
            .service(crate::handlers::statistics::clear_cache)
            .service(crate::handlers::statistics_details::details),
    )
    .await;
    let timezone = crate::system_time::snapshot().document.timezone;
    let base = json!({"start_at":"2026-09-01T00:00:00Z","end_at":"2026-09-03T00:00:00Z","timezone":timezone});
    let mut request = base.clone();
    request["data_type"] = json!("scanners");
    request["group_by"] = json!("scanner");
    request["metrics"] = json!(["completed", "success_rate"]);
    request["comparison"] = json!("previous");
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/api/analysis/statistics/query")
            .set_json(&request)
            .to_request(),
    )
    .await;
    assert!(response.status().is_success());
    let result: Value = test::read_body_json(response).await;
    assert_eq!(result["data"]["summary"]["completed"], 1);
    assert!(result["data"]["summary"]["p95_ms"].is_null());
    assert_eq!(result["comparison"]["data"]["summary"]["completed"], 0);
    request["metrics"] = json!(["p50_ms", "p95_ms"]);
    let result: Value = test::call_and_read_body_json(
        &app,
        test::TestRequest::post()
            .uri("/api/analysis/statistics/query")
            .set_json(&request)
            .to_request(),
    )
    .await;
    assert_eq!(result["data"]["summary"]["p95_ms"], 1000.0);
    let mut detail = base.clone();
    detail["data_type"] = json!("discovery");
    detail["page_size"] = json!(1);
    let result: Value = test::call_and_read_body_json(
        &app,
        test::TestRequest::post()
            .uri("/api/analysis/statistics/details")
            .set_json(&detail)
            .to_request(),
    )
    .await;
    assert_eq!(result["data"]["rows"][0]["ip_address"], "192.0.2.1");
    assert_eq!(result["data"]["has_more"], true);
    detail["after"] = result["data"]["next_cursor"].clone();
    let result: Value = test::call_and_read_body_json(
        &app,
        test::TestRequest::post()
            .uri("/api/analysis/statistics/details")
            .set_json(&detail)
            .to_request(),
    )
    .await;
    assert_eq!(result["data"]["rows"][0]["ip_address"], "192.0.2.2");
    assert_eq!(result["data"]["has_more"], false);
    let mut detail = base.clone();
    detail["data_type"] = json!("port");
    detail["category"] = json!("443");
    let result: Value = test::call_and_read_body_json(
        &app,
        test::TestRequest::post()
            .uri("/api/analysis/statistics/details")
            .set_json(&detail)
            .to_request(),
    )
    .await;
    assert_eq!(result["data"]["rows"][0]["count"], 2);
    assert_eq!(result["data"]["rows"].as_array().unwrap().len(), 1);
    for kind in ["tasks", "scanners"] {
        let mut detail = base.clone();
        detail["data_type"] = json!(kind);
        let result: Value = test::call_and_read_body_json(
            &app,
            test::TestRequest::post()
                .uri("/api/analysis/statistics/details")
                .set_json(&detail)
                .to_request(),
        )
        .await;
        assert_eq!(result["data"]["rows"].as_array().unwrap().len(), 1);
    }
    assert_eq!(
        test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/api/analysis/statistics/cache")
                .to_request()
        )
        .await
        .status(),
        403
    );
    assert_eq!(
        test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/analysis/statistics/cache/clear")
                .set_json(json!({"expected_revision":1}))
                .to_request()
        )
        .await
        .status(),
        403
    );
    cleanup(&pool, &schema).await;
}
