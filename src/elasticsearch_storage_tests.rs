//! Protocol tests with a disposable PG schema and a local HTTP fixture, not an ES cluster.
use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Mutex;

#[derive(Default)]
struct FixtureState {
    requests: Vec<String>,
    documents: BTreeMap<(String, String), Value>,
    fail_path: Option<String>,
    delay_path: Option<String>,
    delay_ms: u64,
    dns_generation: usize,
}

struct EsFixture {
    url: String,
    state: Arc<Mutex<FixtureState>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl EsFixture {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(FixtureState::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_state = state.clone();
        let thread_stop = stop.clone();
        let thread = std::thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                let Ok((mut socket, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut data = Vec::new();
                let mut buffer = [0; 8192];
                let (header_end, length) = loop {
                    let count = socket.read(&mut buffer).unwrap();
                    assert!(count > 0);
                    data.extend_from_slice(&buffer[..count]);
                    if let Some(position) = data.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&data[..position]);
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                line.to_lowercase()
                                    .strip_prefix("content-length:")?
                                    .trim()
                                    .parse::<usize>()
                                    .ok()
                            })
                            .unwrap_or(0);
                        break (position + 4, length);
                    }
                };
                while data.len() < header_end + length {
                    let count = socket.read(&mut buffer).unwrap();
                    assert!(count > 0);
                    data.extend_from_slice(&buffer[..count]);
                }
                let header = String::from_utf8_lossy(&data[..header_end]);
                let first = header.lines().next().unwrap();
                let mut parts = first.split_whitespace();
                let method = parts.next().unwrap();
                let path = parts.next().unwrap();
                let body = String::from_utf8_lossy(&data[header_end..header_end + length]);
                let (fail, delay_ms) = {
                    let mut state = thread_state.lock().unwrap();
                    state.requests.push(format!("{method} {path}"));
                    (
                        state
                            .fail_path
                            .as_ref()
                            .is_some_and(|needle| path.contains(needle)),
                        state
                            .delay_path
                            .as_ref()
                            .filter(|needle| path.contains(*needle))
                            .map_or(0, |_| state.delay_ms),
                    )
                };
                if delay_ms > 0 {
                    std::thread::sleep(Duration::from_millis(delay_ms));
                }
                let mut state = thread_state.lock().unwrap();
                let response = if fail {
                    json!({"error": "fixture failure"})
                } else {
                    fixture_response(&mut state, method, path, &body)
                };
                let response = if method == "HEAD" {
                    String::new()
                } else {
                    response.to_string()
                };
                write!(socket, "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    if fail { "503 Unavailable" } else { "200 OK" }, response.len(), response).unwrap();
            }
        });
        Self {
            url,
            state,
            stop,
            thread: Some(thread),
        }
    }

    fn service(&self) -> ElasticsearchService {
        ElasticsearchService::new(ElasticsearchConfig {
            url: self.url.clone(),
            bulk_max_retries: 0,
            ..ElasticsearchConfig::default()
        })
        .unwrap()
    }
}

impl Drop for EsFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.take().unwrap().join().unwrap();
    }
}

fn fixture_response(state: &mut FixtureState, _method: &str, path: &str, body: &str) -> Value {
    if path == "/" {
        return json!({"version": {"number": "9.5.3"}});
    }
    if path.starts_with("/_data_stream/") {
        return json!({"data_streams": [{"indices": [{"index_name": format!(".ds-dns-{}", state.dns_generation)}]}]});
    }
    if path.starts_with("/_bulk") {
        let lines: Vec<Value> = body
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let mut items = Vec::new();
        for pair in lines.chunks_exact(2) {
            let (operation, action) = pair[0].as_object().unwrap().iter().next().unwrap();
            let requested_index = action["_index"].as_str().unwrap();
            let backing_create = operation == "create" && requested_index.starts_with(".ds-");
            let actual_index = if requested_index == "network-mapping-dns-observations" {
                format!(".ds-dns-{}", state.dns_generation)
            } else {
                requested_index.to_owned()
            };
            let key = (
                actual_index.clone(),
                action["_id"].as_str().unwrap().to_owned(),
            );
            let conflict =
                !backing_create && operation == "create" && state.documents.contains_key(&key);
            if !backing_create && !conflict {
                let document = if operation == "update" {
                    pair[1]["script"]["params"]["doc"].clone()
                } else {
                    pair[1].clone()
                };
                state.documents.insert(key, document);
            }
            let status = if backing_create {
                400
            } else if conflict {
                409
            } else {
                201
            };
            let mut result = json!({
                "status": status,
                "_index": actual_index,
                "_id": action["_id"]
            });
            if backing_create {
                result["error"] = json!({"reason":
                    "index request with op_type=create targeting backing indices is disallowed"
                });
            }
            items.push(json!({(operation): result}));
        }
        return json!({
            "errors": items.iter().any(|item| item.as_object().unwrap().values().any(|action| {
                action["status"].as_u64().is_some_and(|status| status >= 300)
            })),
            "items": items
        });
    }
    if path.contains("_mget") {
        let request: Value = serde_json::from_str(body).unwrap();
        let docs = request["docs"].as_array().unwrap().iter().map(|doc| {
            let key = (doc["_index"].as_str().unwrap().to_owned(), doc["_id"].as_str().unwrap().to_owned());
            json!({"found": true, "_source": state.documents.get(&key).unwrap(), "_id": doc["_id"], "_index": doc["_index"]})
        }).collect::<Vec<_>>();
        return json!({"docs": docs});
    }
    if path.contains("_count") {
        return json!({"count": state.documents.keys().filter(|(index, _)| index.contains("scan-observations")).count(), "_shards": {"failed":0}});
    }
    if path.contains("_search") {
        let request: Value = serde_json::from_str(body).unwrap();
        if path.contains("network-mapping-dns-observations/_search")
            && request.pointer("/query/bool/filter").is_some()
        {
            let hits = state
                .documents
                .iter()
                .filter(|((index, _), _)| index.starts_with(".ds-dns-"))
                .map(|((index, id), _)| json!({"_index": index, "_id": id}))
                .collect::<Vec<_>>();
            return json!({
                "hits": {"total": {"value": hits.len(), "relation": "eq"}, "hits": hits},
                "_shards": {"failed": 0}
            });
        }
        if request.pointer("/aggs/indices").is_some() {
            return json!({"aggregations": {"indices": {"buckets": []}}, "_shards": {"failed":0}});
        }
        let hits: Vec<_> = state
            .documents
            .iter()
            .filter(|((index, _), _)| path.contains(index))
            .map(|((_, id), doc)| json!({"_source": doc, "sort": [id]}))
            .collect();
        let ips: std::collections::BTreeSet<_> = hits
            .iter()
            .filter_map(|hit| hit["_source"]["ip"].as_str())
            .collect();
        return json!({"hits": {"total": {"value": hits.len()}, "hits": hits}, "_shards": {"failed":0},
            "aggregations": {"ips": {"buckets": ips.iter().map(|ip| json!({"key": {"ip":ip}})).collect::<Vec<_>>()}}});
    }
    json!({"acknowledged": true, "_shards": {"failed":0}})
}

async fn isolated_pool() -> (Pool, String) {
    isolated_pool_with_size(8).await
}

async fn isolated_pool_with_size(max_size: usize) -> (Pool, String) {
    let mut config: tokio_postgres::Config = std::env::var("STORAGE_TEST_DATABASE_URL")
        .expect("disposable PG URL")
        .parse()
        .unwrap();
    let schema = format!("storage_{}", Uuid::new_v4().simple());
    config.options(format!("-c search_path={schema}"));
    let manager = deadpool_postgres::Manager::new(config, tokio_postgres::NoTls);
    let pool = Pool::builder(manager).max_size(max_size).build().unwrap();
    let client = pool.get().await.unwrap();
    client
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    client
        .batch_execute(include_str!("../source/database/init.sql"))
        .await
        .unwrap();
    (pool, schema)
}

async fn seed_execution(pool: &Pool) {
    pool.get().await.unwrap().batch_execute(
        "INSERT INTO users(id,username,password) VALUES(1,'fixture','unused');
         INSERT INTO scan_task(id,user_id,task_id,task_initiator,task_target) VALUES(1,1,'task','fixture',ARRAY['192.0.2.1'::inet]);
         INSERT INTO scan_task_execution(id,execution_id,task_id,execution_status,result_ip_count,result_port_count,result_observation_count)
         VALUES(1,'execution',1,'running',0,0,0);"
    ).await.unwrap();
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and local HTTP sockets"]
async fn fresh_install_restart_pending_and_missing_index_gate() {
    let (pool, schema) = isolated_pool().await;
    let fixture = EsFixture::start();
    let service = fixture.service();
    service.validate_scan_cutover(&pool).await.unwrap();
    let client = pool.get().await.unwrap();
    client
        .batch_execute(include_str!("../source/database/init.sql"))
        .await
        .unwrap();
    for name in ["ips", "ports", "scan_observation", "asset_endpoint_current"] {
        assert!(
            !client
                .query_one("SELECT to_regclass($1) IS NOT NULL", &[&name])
                .await
                .unwrap()
                .get::<_, bool>(0)
        );
    }
    drop(client);
    seed_execution(&pool).await;
    pool.get().await.unwrap().batch_execute("INSERT INTO scan_result_batch(execution_id,upload_id,batch_index,is_final,observation_count) VALUES(1,'upload',0,true,0); INSERT INTO scan_projection_outbox(execution_id) VALUES(1);").await.unwrap();
    service.validate_scan_cutover(&pool).await.unwrap(); // pending must not brick restart
    fixture.state.lock().unwrap().fail_path = Some("endpoints-current".into());
    assert!(
        service
            .validate_scan_cutover(&pool)
            .await
            .unwrap_err()
            .contains("不可用")
    );
    fixture.state.lock().unwrap().fail_path = None;
    pool.get()
        .await
        .unwrap()
        .batch_execute("ALTER TABLE scan_result_batch DROP COLUMN storage_backend")
        .await
        .unwrap();
    // Upgrading a pre-backend-column schema must classify existing receipts as PG.
    pool.get()
        .await
        .unwrap()
        .batch_execute(include_str!("../source/database/init.sql"))
        .await
        .unwrap();
    assert_eq!(
        pool.get()
            .await
            .unwrap()
            .query_one("SELECT storage_backend FROM scan_result_batch", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        "postgres"
    );
    assert!(
        service
            .validate_scan_cutover(&pool)
            .await
            .unwrap_err()
            .contains("未迁移")
    );
    assert!(
        !fixture
            .state
            .lock()
            .unwrap()
            .requests
            .iter()
            .any(|path| path.contains("assets-v1"))
    );
    pool.get()
        .await
        .unwrap()
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and local HTTP sockets"]
async fn pg_migration_is_explicit_repeatable_and_checks_batch_completeness() {
    let (pool, schema) = isolated_pool().await;
    seed_execution(&pool).await;
    let fixture = EsFixture::start();
    let service = fixture.service();
    crate::scan_migration::prepare(&pool, &NoopProgressReporter)
        .await
        .unwrap();
    pool.get().await.unwrap().batch_execute(
        "INSERT INTO scan_result_batch(id,execution_id,upload_id,batch_index,is_final,observation_count,storage_backend) VALUES(1,1,'upload',0,true,1,'postgres');
         INSERT INTO ips(task_id,execution_id,ip_address) VALUES(1,1,'192.0.2.1');"
    ).await.unwrap();
    assert!(service.validate_scan_cutover(&pool).await.is_err());
    assert!(
        service
            .migrate_scan_data(&pool)
            .await
            .unwrap_err()
            .contains("观察数量")
    );
    pool.get().await.unwrap().batch_execute(
        "INSERT INTO scan_observation(execution_id,batch_id,observation_key,kind,ip_address,port,protocol,source,observed_at)
         VALUES(1,1,'observation','port','192.0.2.1',443,'tcp','fixture','2026-08-01T00:00:00Z');"
    ).await.unwrap();
    let report = service.migrate_scan_data(&pool).await.unwrap();
    assert_eq!(report.batches, 1);
    assert_eq!(report.observations, 1);
    service.validate_scan_cutover(&pool).await.unwrap();
    let documents = fixture.state.lock().unwrap().documents.len();
    service.migrate_scan_data(&pool).await.unwrap();
    assert_eq!(fixture.state.lock().unwrap().documents.len(), documents);
    assert_eq!(
        pool.get()
            .await
            .unwrap()
            .query_one(
                "SELECT storage_backend FROM scan_result_batch WHERE id=1",
                &[]
            )
            .await
            .unwrap()
            .get::<_, String>(0),
        "elasticsearch"
    );
    pool.get()
        .await
        .unwrap()
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

fn dns_test_context() -> ScanBatchContext {
    ScanBatchContext {
        task_id: "task".into(),
        execution_id: "execution".into(),
        user_id: 1,
        task_source: "manual".into(),
        scanner_id: "scanner".into(),
        scanner_name: None,
        upload_id: "upload".into(),
        batch_index: 0,
        is_final: true,
    }
}

fn dns_test_observation(name: &str) -> DnsObservation {
    DnsObservation {
        observed_at: 1_788_883_200_000,
        question: crate::dns::DnsQuestion {
            name: name.into(),
            record_type: "A".into(),
            class: "IN".into(),
        },
        response_code: "NXDOMAIN".into(),
        authoritative: false,
        truncated: false,
        dnssec_authenticated: false,
        answers: Vec::new(),
        authority: Vec::new(),
        additional: Vec::new(),
        resolver_ip: None,
        resolver_id: None,
        resolver_label: None,
        resolver_port: None,
        resolver_transport: None,
        latency_ms: Some(1),
    }
}

#[tokio::test]
async fn dns_retry_reconciles_through_data_stream_across_rollover() {
    let fixture = EsFixture::start();
    let service = fixture.service();
    let context = dns_test_context();
    let observations = vec![dns_test_observation("example.com")];
    let first = service
        .persist_dns_observations(&context, "default", &observations, DnsWriteMode::Fresh)
        .await
        .unwrap();
    fixture.state.lock().unwrap().dns_generation = 1;
    let retried = service
        .persist_dns_observations(&context, "default", &observations, DnsWriteMode::Reconcile)
        .await
        .unwrap();
    assert_eq!(first, retried);
    assert_eq!(first[0], ".ds-dns-0");
    assert_eq!(first[1], "network-mapping-dns-records-v1");
    let state = fixture.state.lock().unwrap();
    assert_eq!(
        state
            .documents
            .keys()
            .filter(|(index, _)| index.starts_with(".ds-dns-"))
            .count(),
        1
    );
    assert_eq!(
        state
            .requests
            .iter()
            .filter(|request| request.contains("/_refresh"))
            .count(),
        1
    );
    assert_eq!(
        state
            .requests
            .iter()
            .filter(|request| request.contains("/_search"))
            .count(),
        1
    );
    assert_eq!(
        state
            .requests
            .iter()
            .filter(|request| request.contains("/_bulk"))
            .count(),
        1
    );
}

#[tokio::test]
async fn dns_retry_only_writes_missing_documents_after_rollover() {
    let fixture = EsFixture::start();
    let service = fixture.service();
    let context = dns_test_context();
    let observations = vec![
        dns_test_observation("example.com"),
        dns_test_observation("www.example.com"),
    ];
    service
        .persist_dns_observations(&context, "default", &observations, DnsWriteMode::Fresh)
        .await
        .unwrap();
    {
        let mut state = fixture.state.lock().unwrap();
        let removed = state
            .documents
            .keys()
            .find(|(index, _)| index.starts_with(".ds-dns-"))
            .cloned()
            .unwrap();
        state.documents.remove(&removed);
        state.dns_generation = 1;
    }

    let references = service
        .persist_dns_observations(&context, "default", &observations, DnsWriteMode::Reconcile)
        .await
        .unwrap();
    assert_eq!(
        references,
        vec![
            ".ds-dns-0".to_owned(),
            ".ds-dns-1".to_owned(),
            "network-mapping-dns-records-v1".to_owned()
        ]
    );
    let state = fixture.state.lock().unwrap();
    assert_eq!(
        state
            .documents
            .keys()
            .filter(|(index, _)| index.starts_with(".ds-dns-"))
            .count(),
        2
    );
}

#[tokio::test]
async fn dns_reconciliation_rejects_duplicate_id_across_backing_indices() {
    let fixture = EsFixture::start();
    let service = fixture.service();
    let context = dns_test_context();
    let observations = vec![dns_test_observation("example.com")];
    service
        .persist_dns_observations(&context, "default", &observations, DnsWriteMode::Fresh)
        .await
        .unwrap();
    {
        let mut state = fixture.state.lock().unwrap();
        let ((_, id), document) = state
            .documents
            .iter()
            .find(|((index, _), _)| index.starts_with(".ds-dns-"))
            .map(|(key, document)| (key.clone(), document.clone()))
            .unwrap();
        state.documents.insert((".ds-dns-1".into(), id), document);
    }

    let error = service
        .persist_dns_observations(&context, "default", &observations, DnsWriteMode::Reconcile)
        .await
        .unwrap_err();
    assert!(error.contains("跨 backing index 重复"));
}

async fn seed_dns_upload(pool: &Pool) -> crate::ScannerResultUpload {
    seed_execution(pool).await;
    let scanner = "00000000-0000-0000-0000-000000000001";
    let task = "00000000-0000-0000-0000-000000000002";
    let token_hash = crate::hash_scanner_token("fixture-token", "fixture-pepper").unwrap();
    let client = pool.get().await.unwrap();
    client.execute("INSERT INTO scanner_info(scanner_id,create_user,runtime_token_hash,is_enable) VALUES($1,1,$2,true)", &[&scanner,&token_hash]).await.unwrap();
    client
        .execute(
            "UPDATE scan_task SET task_id=$1, task_kind='dns' WHERE id=1",
            &[&task],
        )
        .await
        .unwrap();
    client.execute("UPDATE scan_task_execution SET assigned_scanner_id=$1,task_start_time=1785542400000 WHERE id=1", &[&scanner]).await.unwrap();
    drop(client);
    serde_json::from_value(json!({
        "protocol_version": 2,
        "scanner_id": scanner,
        "task_id": task,
        "upload_id": "00000000-0000-0000-0000-000000000003",
        "batch_index": 0,
        "is_final": false,
        "observations": [{
            "kind": "dns",
            "observed_at": 1_788_883_200_000_i64,
            "question": {"name": "example.com", "type": "A", "class": "IN"},
            "response_code": "NXDOMAIN",
            "authoritative": false,
            "truncated": false,
            "dnssec_authenticated": false,
            "answers": [],
            "authority": [],
            "additional": [],
            "resolver_ip": null,
            "resolver_id": null,
            "resolver_label": null,
            "resolver_port": null,
            "resolver_transport": null,
            "latency_ms": 1
        }]
    }))
    .unwrap()
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and local HTTP sockets"]
async fn dns_batch_write_lease_blocks_overlap_and_recovers_after_expiry() {
    let (pool, schema) = isolated_pool().await;
    let fixture = EsFixture::start();
    let service = fixture.service();
    let upload = seed_dns_upload(&pool).await;
    let maxmind = crate::maxmind::MaxMindState::from_directory("/tmp/nm-es-no-maxmind");
    let follow_up = crate::dns_follow_up::DnsFollowUpConfig::default();

    fixture.state.lock().unwrap().fail_path = Some("_bulk".into());
    let failed_write = crate::save_scanner_results(
        &pool,
        &maxmind,
        &service,
        &follow_up,
        &upload,
        "fixture-token",
        "fixture-pepper",
    )
    .await;
    assert!(
        matches!(
            &failed_write,
            Err(crate::SaveScannerResultsError::Storage(_))
        ),
        "unexpected first write result: {failed_write:?}"
    );
    assert!(matches!(
        crate::save_scanner_results(
            &pool,
            &maxmind,
            &service,
            &follow_up,
            &upload,
            "fixture-token",
            "fixture-pepper"
        )
        .await,
        Err(crate::SaveScannerResultsError::BatchBusy { .. })
    ));

    fixture.state.lock().unwrap().fail_path = None;
    pool.get()
        .await
        .unwrap()
        .execute(
            "UPDATE scan_result_batch SET write_lease_expires_at = clock_timestamp() - INTERVAL '1 second'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        crate::save_scanner_results(
            &pool,
            &maxmind,
            &service,
            &follow_up,
            &upload,
            "fixture-token",
            "fixture-pepper"
        )
        .await
        .unwrap(),
        1
    );
    let receipt = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT storage_backend, write_token IS NULL, write_attempts FROM scan_result_batch",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(receipt.get::<_, String>(0), "elasticsearch");
    assert!(receipt.get::<_, bool>(1));
    assert_eq!(receipt.get::<_, i32>(2), 2);

    pool.get()
        .await
        .unwrap()
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and local HTTP sockets"]
async fn dns_elasticsearch_wait_does_not_hold_the_postgres_connection() {
    let (pool, schema) = isolated_pool_with_size(1).await;
    let fixture = EsFixture::start();
    let service = fixture.service();
    let upload = seed_dns_upload(&pool).await;
    let maxmind = crate::maxmind::MaxMindState::from_directory("/tmp/nm-es-no-maxmind");
    let follow_up = crate::dns_follow_up::DnsFollowUpConfig::default();
    {
        let mut state = fixture.state.lock().unwrap();
        state.delay_path = Some("_bulk".into());
        state.delay_ms = 750;
    }

    let write = crate::save_scanner_results(
        &pool,
        &maxmind,
        &service,
        &follow_up,
        &upload,
        "fixture-token",
        "fixture-pepper",
    );
    let pool_probe = async {
        loop {
            if fixture
                .state
                .lock()
                .unwrap()
                .requests
                .iter()
                .any(|request| request.contains("/_bulk"))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        tokio::time::timeout(Duration::from_millis(250), pool.get())
            .await
            .is_ok()
    };
    let (write_result, pool_was_available) = tokio::join!(write, pool_probe);
    assert!(
        pool_was_available,
        "ES I/O must not retain the PG connection"
    );
    assert_eq!(write_result.unwrap(), 1);

    pool.get()
        .await
        .unwrap()
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires STORAGE_TEST_CONFIG_PATH and creates isolated local ES resources"]
async fn live_elasticsearch_accepts_fresh_and_reconciled_dns_writes() {
    let config_path = std::env::var("STORAGE_TEST_CONFIG_PATH").expect("test config path");
    let mut config = crate::config::Config::from_file(config_path).elasticsearch;
    let suffix = Uuid::new_v4().simple().to_string();
    config.dns_observation_data_stream = format!("nm-test-dns-{suffix}");
    config.dns_record_index = format!("nm-test-dns-records-{suffix}");
    let stream = config.dns_observation_data_stream.clone();
    let record_index = config.dns_record_index.clone();
    let template = format!("{stream}-template");
    let service = ElasticsearchService::new(config).unwrap();
    let mut context = dns_test_context();
    context.execution_id = format!("execution-{suffix}");
    context.upload_id = format!("upload-{suffix}");
    let observations = vec![dns_test_observation("live-test.example")];

    let first = service
        .persist_dns_observations(&context, "default", &observations, DnsWriteMode::Fresh)
        .await;
    let recovered = if first.is_ok() {
        service
            .persist_dns_observations(&context, "default", &observations, DnsWriteMode::Reconcile)
            .await
    } else {
        Err("fresh write failed".to_owned())
    };

    for path in [
        format!("/_data_stream/{stream}"),
        format!("/{record_index}"),
        format!("/_index_template/{template}"),
    ] {
        let _ = service
            .send_json_request(
                ElasticsearchOperation::IndexAdmin,
                reqwest::Method::DELETE,
                &path,
                |request| request,
            )
            .await;
    }

    let first = first.unwrap();
    let recovered = recovered.unwrap();
    assert_eq!(first, recovered);
    assert_eq!(
        first
            .iter()
            .filter(|index| index.starts_with(".ds-nm-test-dns-"))
            .count(),
        1
    );
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn task_claim_keeps_selected_priority_then_uses_public_queue() {
    let (pool, schema) = isolated_pool().await;
    let scanner = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let second_scanner = Uuid::parse_str("00000000-0000-0000-0000-000000000004").unwrap();
    let selected_task = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
    let public_task = Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();
    let token_hash = crate::hash_scanner_token("fixture-token", "fixture-pepper").unwrap();
    let second_token_hash =
        crate::hash_scanner_token("second-fixture-token", "fixture-pepper").unwrap();
    let client = pool.get().await.unwrap();
    client
        .execute(
            "INSERT INTO users(id,username,password) VALUES(1,'fixture','unused')",
            &[],
        )
        .await
        .unwrap();
    client.execute("INSERT INTO scanner_info(scanner_id,create_user,runtime_token_hash,is_enable) VALUES($1,1,$2,true)", &[&scanner.to_string(),&token_hash]).await.unwrap();
    client.execute("INSERT INTO scanner_info(scanner_id,create_user,runtime_token_hash,is_enable) VALUES($1,1,$2,true)", &[&second_scanner.to_string(),&second_token_hash]).await.unwrap();
    client.execute("INSERT INTO scan_task(id,user_id,task_id,task_initiator,task_target,task_level,task_create_time) VALUES(1,1,$1,'fixture',ARRAY['192.0.2.1'::inet],1,2),(2,1,$2,'fixture',ARRAY['192.0.2.2'::inet],4,1)", &[&selected_task.to_string(), &public_task.to_string()]).await.unwrap();
    client.execute("INSERT INTO scan_task_execution(id,execution_id,task_id,requested_scanner_id) VALUES(1,'selected-execution',1,$1),(2,'public-execution',2,NULL)", &[&scanner.to_string()]).await.unwrap();
    drop(client);

    let selected = crate::apply_task(&pool, scanner, "fixture-token", "fixture-pepper")
        .await
        .unwrap();
    assert_eq!(selected.task_id, selected_task);

    let mut client = pool.get().await.unwrap();
    let transaction = client.transaction().await.unwrap();
    transaction
        .execute(
            "UPDATE scan_task_execution SET execution_status='succeeded', lease_expires_at=NULL WHERE id=1",
            &[],
        )
        .await
        .unwrap();
    crate::refresh_task_aggregate(&transaction, 1)
        .await
        .unwrap();
    transaction.commit().await.unwrap();

    let public = crate::apply_task(&pool, scanner, "fixture-token", "fixture-pepper")
        .await
        .unwrap();
    assert_eq!(public.task_id, public_task);

    pool.get()
        .await
        .unwrap()
        .execute(
            "UPDATE scan_task_execution SET lease_expires_at = $1 WHERE id=2",
            &[&(crate::get_unix_epoch_ms() - 1)],
        )
        .await
        .unwrap();
    let reclaimed = crate::apply_task(
        &pool,
        second_scanner,
        "second-fixture-token",
        "fixture-pepper",
    )
    .await
    .unwrap();
    assert_eq!(reclaimed.task_id, public_task);

    pool.get()
        .await
        .unwrap()
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn concurrent_task_claims_do_not_assign_one_execution_twice() {
    let (pool, schema) = isolated_pool().await;
    let first_scanner = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let second_scanner = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
    let task_id = Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();
    let first_hash = crate::hash_scanner_token("first-token", "fixture-pepper").unwrap();
    let second_hash = crate::hash_scanner_token("second-token", "fixture-pepper").unwrap();
    let client = pool.get().await.unwrap();
    client
        .batch_execute("INSERT INTO users(id,username,password) VALUES(1,'fixture','unused')")
        .await
        .unwrap();
    client.execute("INSERT INTO scanner_info(scanner_id,create_user,runtime_token_hash,is_enable) VALUES($1,1,$2,true),($3,1,$4,true)", &[&first_scanner.to_string(), &first_hash, &second_scanner.to_string(), &second_hash]).await.unwrap();
    client.execute("INSERT INTO scan_task(id,user_id,task_id,task_initiator,task_target) VALUES(1,1,$1,'fixture',ARRAY['192.0.2.1'::inet])", &[&task_id.to_string()]).await.unwrap();
    client
        .batch_execute(
            "INSERT INTO scan_task_execution(id,execution_id,task_id) VALUES(1,'execution',1)",
        )
        .await
        .unwrap();
    drop(client);

    let (first, second) = tokio::join!(
        crate::apply_task(&pool, first_scanner, "first-token", "fixture-pepper"),
        crate::apply_task(&pool, second_scanner, "second-token", "fixture-pepper")
    );
    let successes = [&first, &second]
        .into_iter()
        .filter(|result| result.is_ok())
        .count();
    assert_eq!(successes, 1);
    assert!(matches!(first, Ok(_) | Err(crate::ApplyTaskError::NoTask)));
    assert!(matches!(second, Ok(_) | Err(crate::ApplyTaskError::NoTask)));

    let execution = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT execution_status, assigned_scanner_id FROM scan_task_execution WHERE id=1",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(execution.get::<_, String>(0), "running");
    assert!(matches!(
        execution.get::<_, Option<String>>(1).as_deref(),
        Some(value) if value == first_scanner.to_string() || value == second_scanner.to_string()
    ));

    pool.get()
        .await
        .unwrap()
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn no_task_result_commits_bounded_cancel_reaping() {
    let (pool, schema) = isolated_pool().await;
    let scanner = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let task_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
    let token_hash = crate::hash_scanner_token("fixture-token", "fixture-pepper").unwrap();
    let client = pool.get().await.unwrap();
    client
        .batch_execute("INSERT INTO users(id,username,password) VALUES(1,'fixture','unused')")
        .await
        .unwrap();
    client.execute("INSERT INTO scanner_info(scanner_id,create_user,runtime_token_hash,is_enable) VALUES($1,1,$2,true)", &[&scanner.to_string(), &token_hash]).await.unwrap();
    client.execute("INSERT INTO scan_task(id,user_id,task_id,task_initiator,task_target,task_status) VALUES(1,1,$1,'fixture',ARRAY['192.0.2.1'::inet],'running')", &[&task_id.to_string()]).await.unwrap();
    client.execute("INSERT INTO scan_task_execution(id,execution_id,task_id,execution_status,assigned_scanner_id,lease_expires_at,cancel_requested) VALUES(1,'execution',1,'running','other-scanner',$1,true)", &[&(crate::get_unix_epoch_ms() - 1)]).await.unwrap();
    drop(client);

    assert!(matches!(
        crate::apply_task(&pool, scanner, "fixture-token", "fixture-pepper").await,
        Err(crate::ApplyTaskError::NoTask)
    ));
    let status: String = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT execution_status FROM scan_task_execution WHERE id=1",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(status, "cancelled");

    pool.get()
        .await
        .unwrap()
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

fn plan_contains_node(value: &Value, node_type: &str, relation: Option<&str>) -> bool {
    match value {
        Value::Array(values) => values
            .iter()
            .any(|value| plan_contains_node(value, node_type, relation)),
        Value::Object(values) => {
            let matches = values.get("Node Type").and_then(Value::as_str) == Some(node_type)
                && relation.is_none_or(|relation| {
                    values.get("Relation Name").and_then(Value::as_str) == Some(relation)
                });
            matches
                || values
                    .values()
                    .any(|value| plan_contains_node(value, node_type, relation))
        }
        _ => false,
    }
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and inserts 200k synthetic tasks"]
async fn task_claim_plan_avoids_global_scans_and_disk_sort_at_scale() {
    let (pool, schema) = isolated_pool().await;
    let scanner = "00000000-0000-0000-0000-000000000001";
    let mut client = pool.get().await.unwrap();
    client
        .batch_execute(
            "INSERT INTO users(id,username,password) VALUES(1,'fixture','unused');
             INSERT INTO scanner_info(scanner_id,create_user,is_enable) VALUES
                 ('00000000-0000-0000-0000-000000000001',1,true);
             INSERT INTO scan_task(id,user_id,task_id,task_initiator,task_target,task_level,task_create_time)
             SELECT value, 1, LPAD(value::TEXT, 36, '0'), 'fixture',
                    ARRAY['192.0.2.1'::INET], value % 5, value
             FROM generate_series(1, 200000) AS value;
             INSERT INTO scan_task_execution(id,execution_id,task_id)
             SELECT value, 'execution-' || value, value
             FROM generate_series(1, 200000) AS value;
             ANALYZE scan_task;
             ANALYZE scan_task_execution;",
        )
        .await
        .unwrap();
    let transaction = client.transaction().await.unwrap();
    let selected_plan: Value = transaction
        .query_one(
            "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) \
             SELECT t.id AS task_pk, e.id AS execution_pk \
             FROM scan_task_execution e \
             JOIN scan_task t ON t.id = e.task_id \
             JOIN scanner_info s ON s.scanner_id = $1 \
             WHERE e.execution_status = 'pending' AND e.requested_scanner_id = $1 \
               AND t.task_status IN ('pending', 'running') \
             ORDER BY t.task_level DESC, t.task_create_time, t.id, e.id \
             FOR UPDATE OF e SKIP LOCKED LIMIT 1;",
            &[&scanner],
        )
        .await
        .unwrap()
        .get(0);
    let plan: Value = transaction
        .query_one(
            "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) \
             SELECT t.id AS task_pk, e.execution_pk, t.user_id, t.task_id, \
                 CASE WHEN t.task_kind = 'dns' THEN t.dns_targets ELSE t.task_target::text[] END AS task_target, \
                 t.task_port, t.address_family, t.scan_plan, t.dns_resolvers \
             FROM scan_task t \
             JOIN scanner_info s ON s.scanner_id = $2 \
             JOIN LATERAL ( \
                 SELECT candidate.id AS execution_pk \
                 FROM scan_task_execution candidate \
                 WHERE candidate.task_id = t.id AND ( \
                     (candidate.execution_status = 'pending' AND candidate.requested_scanner_id IS NULL) \
                     OR (candidate.execution_status = 'running' \
                         AND candidate.maintenance_hold = FALSE \
                         AND candidate.cancel_requested = FALSE \
                         AND (candidate.lease_expires_at IS NULL OR candidate.lease_expires_at < $1) \
                         AND (candidate.requested_scanner_id IS NULL OR candidate.requested_scanner_id = $2)) \
                 ) \
                 ORDER BY candidate.id FOR UPDATE SKIP LOCKED LIMIT 1 \
             ) e ON TRUE \
             WHERE t.task_status IN ('pending', 'running') \
               AND ((t.address_family = 'ipv4' AND s.supports_ipv4 AND s.ipv4_ready) \
                 OR (t.address_family = 'ipv6' AND s.supports_ipv6 AND s.ipv6_ready)) \
               AND (t.scan_profile = 'legacy' OR s.scan_capabilities->'profiles' ? t.scan_profile) \
               AND (jsonb_array_length(t.dns_resolvers) = 0 \
                 OR COALESCE((s.scan_capabilities->>'explicit_dns_resolvers')::BOOLEAN, FALSE)) \
             ORDER BY t.task_level DESC, t.task_create_time, t.id, e.execution_pk \
             LIMIT 1;",
            &[&crate::get_unix_epoch_ms(), &scanner],
        )
        .await
        .unwrap()
        .get(0);
    transaction.rollback().await.unwrap();
    assert!(!plan_contains_node(
        &selected_plan,
        "Seq Scan",
        Some("scan_task")
    ));
    assert!(!plan_contains_node(
        &selected_plan,
        "Seq Scan",
        Some("scan_task_execution")
    ));
    assert!(!plan_contains_node(&plan, "Seq Scan", Some("scan_task")));
    assert!(!plan_contains_node(
        &plan,
        "Seq Scan",
        Some("scan_task_execution")
    ));
    assert!(!plan.to_string().contains("external merge"));
    eprintln!(
        "200k selected/general task claim execution time: {}/{} ms",
        selected_plan
            .pointer("/0/Execution Time")
            .and_then(Value::as_f64)
            .unwrap_or_default(),
        plan.pointer("/0/Execution Time")
            .and_then(Value::as_f64)
            .unwrap_or_default()
    );

    pool.get()
        .await
        .unwrap()
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and local HTTP sockets"]
async fn uploads_recover_without_pg_facts_and_reject_changed_completed_batches() {
    let (pool, schema) = isolated_pool().await;
    seed_execution(&pool).await;
    let fixture = EsFixture::start();
    let service = fixture.service();
    service.validate_scan_cutover(&pool).await.unwrap();
    let scanner = "00000000-0000-0000-0000-000000000001";
    let task = "00000000-0000-0000-0000-000000000002";
    let token_hash = crate::hash_scanner_token("fixture-token", "fixture-pepper").unwrap();
    let client = pool.get().await.unwrap();
    client.execute("INSERT INTO scanner_info(scanner_id,create_user,runtime_token_hash,is_enable) VALUES($1,1,$2,true)", &[&scanner,&token_hash]).await.unwrap();
    client
        .execute("UPDATE scan_task SET task_id=$1 WHERE id=1", &[&task])
        .await
        .unwrap();
    client.execute("UPDATE scan_task_execution SET assigned_scanner_id=$1,task_start_time=1785542400000 WHERE id=1", &[&scanner]).await.unwrap();
    drop(client);
    let payload = json!({"protocol_version":2, "scanner_id":scanner, "task_id":task,
        "upload_id":"00000000-0000-0000-0000-000000000003", "batch_index":0,"is_final":false,
        "observations":[{"kind":"port","ip":"192.0.2.1","port":443,"protocol":"tcp","state":"open","source":"fixture","observed_at":1785542400000_i64}]});
    let upload: crate::ScannerResultUpload = serde_json::from_value(payload.clone()).unwrap();
    let maxmind = crate::maxmind::MaxMindState::from_directory("/tmp/nm-es-no-maxmind");
    let follow_up = crate::dns_follow_up::DnsFollowUpConfig::default();
    fixture.state.lock().unwrap().fail_path = Some("_bulk".into());
    assert!(
        crate::save_scanner_results(
            &pool,
            &maxmind,
            &service,
            &follow_up,
            &upload,
            "fixture-token",
            "fixture-pepper"
        )
        .await
        .is_err()
    );
    let backend: String = pool
        .get()
        .await
        .unwrap()
        .query_one("SELECT storage_backend FROM scan_result_batch", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(backend, "pending");
    fixture.state.lock().unwrap().fail_path = None;
    service.validate_scan_cutover(&pool).await.unwrap();
    assert_eq!(
        crate::save_scanner_results(
            &pool,
            &maxmind,
            &service,
            &follow_up,
            &upload,
            "fixture-token",
            "fixture-pepper"
        )
        .await
        .unwrap(),
        1
    );
    // Force the crash boundary: ES contains facts, but PG still only has a reservation.
    pool.get()
        .await
        .unwrap()
        .batch_execute("UPDATE scan_result_batch SET storage_backend='pending'")
        .await
        .unwrap();
    crate::save_scanner_results(
        &pool,
        &maxmind,
        &service,
        &follow_up,
        &upload,
        "fixture-token",
        "fixture-pepper",
    )
    .await
    .unwrap();
    assert_eq!(
        fixture
            .state
            .lock()
            .unwrap()
            .documents
            .keys()
            .filter(|(index, _)| index.contains("scan-observations"))
            .count(),
        1
    );
    let mut final_upload = upload.clone();
    final_upload.batch_index = Some(1);
    final_upload.is_final = Some(true);
    final_upload.observations.clear();
    crate::save_scanner_results(
        &pool,
        &maxmind,
        &service,
        &follow_up,
        &final_upload,
        "fixture-token",
        "fixture-pepper",
    )
    .await
    .unwrap();
    let row = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT execution_status,result_observation_count FROM scan_task_execution WHERE id=1",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "succeeded");
    assert_eq!(row.get::<_, i64>(1), 1);
    assert_eq!(
        crate::save_scanner_results(
            &pool,
            &maxmind,
            &service,
            &follow_up,
            &upload,
            "fixture-token",
            "fixture-pepper"
        )
        .await
        .unwrap(),
        0
    );
    let mut changed = payload;
    changed["observations"][0]["port"] = json!(80);
    let changed: crate::ScannerResultUpload = serde_json::from_value(changed).unwrap();
    assert!(
        crate::save_scanner_results(
            &pool,
            &maxmind,
            &service,
            &follow_up,
            &changed,
            "fixture-token",
            "fixture-pepper"
        )
        .await
        .is_err()
    );
    assert!(
        fixture
            .state
            .lock()
            .unwrap()
            .requests
            .iter()
            .any(|path| path.contains("scan-observations-v1-*,") && path.contains("_refresh"))
    );
    pool.get()
        .await
        .unwrap()
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[test]
fn failed_service_probe_does_not_advance_successful_service_clock() {
    let context = dns_test_context();
    let failed = json!({"kind": "service", "ip_address": "192.0.2.1", "port": 80,
        "service": null, "banner": null, "data": {"evidence": [], "confidence": 0}});
    let projection = endpoint_projection_document(&context, &failed, 2000);
    assert_eq!(projection["observed_at_ms"], 2000);
    assert!(projection["service_observed_at_ms"].is_null());
    let mut successful = failed;
    successful["service"] = json!("http");
    assert_eq!(
        endpoint_projection_document(&context, &successful, 1000)["service_observed_at_ms"],
        1000
    );
}

#[tokio::test]
#[ignore = "requires STORAGE_TEST_CONFIG_PATH and creates an isolated ES index"]
async fn live_elasticsearch_preserves_successful_web_evidence_after_failed_probes() {
    let config_path = std::env::var("STORAGE_TEST_CONFIG_PATH").expect("test config path");
    let service =
        ElasticsearchService::new(crate::config::Config::from_file(config_path).elasticsearch)
            .unwrap();
    let index = format!("nm-test-web-projection-{}", Uuid::new_v4().simple());
    let context = dns_test_context();
    let test = async {
        service
            .send_json_request(
                ElasticsearchOperation::IndexAdmin,
                Method::PUT,
                &format!("/{index}"),
                |request| request.json(&scan_endpoint_index_definition(0)),
            )
            .await?;
        let success = json!({"kind": "service", "ip_address": "192.0.2.1", "port": 443,
            "service": "https", "title": "Camera", "http_body": "<title>Camera</title>",
            "banner": "HTTP/1.1 200 OK", "tls_subject": "CN=camera"});
        let failed = json!({"kind": "service", "ip_address": "192.0.2.1", "port": 443});
        let mut latest_success = success.clone();
        latest_success["title"] = json!("Updated camera");
        let documents = [
            endpoint_projection_document(&context, &success, 1000),
            endpoint_projection_document(&context, &failed, 2000),
            endpoint_projection_document(&context, &latest_success, 1500),
            endpoint_projection_document(&context, &success, 1200),
            endpoint_projection_document(&context, &failed, 2500),
        ];
        for (position, document) in documents.iter().enumerate() {
            let mut body = String::new();
            append_projection_update(&mut body, &index, "endpoint", document)?;
            let result = service.send_bulk_with_retry("/_bulk", &body, false).await?;
            if result["errors"] != false {
                return Err(format!("projection failed: {result}"));
            }
            let current = service
                .send_json_request(
                    ElasticsearchOperation::ScanQuery,
                    Method::GET,
                    &format!("/{index}/_doc/endpoint"),
                    |request| request,
                )
                .await?;
            let source = &current["_source"];
            let expected_title = if position < 2 {
                "Camera"
            } else {
                "Updated camera"
            };
            if source["title"] != expected_title
                || source["tls_subject"] != "CN=camera"
                || source["http_body"] != "<title>Camera</title>"
            {
                return Err(format!("web evidence lost at step {position}: {source}"));
            }
            if position == 4 {
                if source["service_observed_at_ms"] != 1500 || source["observed_at_ms"] != 2500 {
                    return Err(format!("incorrect observation clocks: {source}"));
                }
                // Promotion must carry the successful-service timestamp, even
                // though a later failed probe set the endpoint timestamp.
                let mut body = String::new();
                append_projection_update(&mut body, &index, "promoted", source)?;
                let newer = endpoint_projection_document(&context, &success, 1750);
                append_projection_update(&mut body, &index, "promoted", &newer)?;
                let result = service.send_bulk_with_retry("/_bulk", &body, false).await?;
                if result["errors"] != false {
                    return Err(format!("promotion failed: {result}"));
                }
                let promoted = service
                    .send_json_request(
                        ElasticsearchOperation::ScanQuery,
                        Method::GET,
                        &format!("/{index}/_doc/promoted"),
                        |request| request,
                    )
                    .await?;
                if promoted["_source"]["title"] != "Camera"
                    || promoted["_source"]["service_observed_at_ms"] != 1750
                {
                    return Err(format!("promotion used endpoint clock: {promoted}"));
                }
            }
        }
        Ok::<(), String>(())
    }
    .await;
    let cleanup = service
        .send_json_request(
            ElasticsearchOperation::IndexAdmin,
            Method::DELETE,
            &format!("/{index}"),
            |request| request,
        )
        .await;
    test.unwrap();
    cleanup.unwrap();
}
