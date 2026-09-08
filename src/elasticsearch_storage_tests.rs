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
                let mut state = thread_state.lock().unwrap();
                state.requests.push(format!("{method} {path}"));
                let fail = state
                    .fail_path
                    .as_ref()
                    .is_some_and(|needle| path.contains(needle));
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
            let key = (
                action["_index"].as_str().unwrap().to_owned(),
                action["_id"].as_str().unwrap().to_owned(),
            );
            let conflict = operation == "create" && state.documents.contains_key(&key);
            if !conflict {
                let document = if operation == "update" {
                    pair[1]["script"]["params"]["doc"].clone()
                } else {
                    pair[1].clone()
                };
                state.documents.insert(key, document);
            }
            items.push(json!({(operation): {"status": if conflict {409} else {201}, "_index": action["_index"], "_id": action["_id"]}}));
        }
        return json!({"errors": items.iter().any(|item| item.to_string().contains("409")), "items": items});
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
    let mut config: tokio_postgres::Config = std::env::var("STORAGE_TEST_DATABASE_URL")
        .expect("disposable PG URL")
        .parse()
        .unwrap();
    let schema = format!("storage_{}", Uuid::new_v4().simple());
    config.options(format!("-c search_path={schema}"));
    let manager = deadpool_postgres::Manager::new(config, tokio_postgres::NoTls);
    let pool = Pool::builder(manager).max_size(8).build().unwrap();
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

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and local HTTP sockets"]
async fn dns_retry_pins_backing_index_across_rollover() {
    let (pool, schema) = isolated_pool().await;
    seed_execution(&pool).await;
    let fixture = EsFixture::start();
    let service = fixture.service();
    pool.get().await.unwrap().batch_execute("INSERT INTO scan_result_batch(execution_id,upload_id,batch_index,is_final,observation_count) VALUES(1,'upload',0,true,0);").await.unwrap();
    let context = ScanBatchContext {
        task_id: "task".into(),
        execution_id: "execution".into(),
        user_id: 1,
        task_source: "manual".into(),
        scanner_id: "scanner".into(),
        scanner_name: None,
        upload_id: "upload".into(),
        batch_index: 0,
        is_final: true,
    };
    let first = service
        .pin_dns_batch_storage(&pool, 1, &context)
        .await
        .unwrap();
    fixture.state.lock().unwrap().dns_generation = 1;
    let retried = service
        .pin_dns_batch_storage(&pool, 1, &context)
        .await
        .unwrap();
    assert_eq!(first, retried);
    assert_eq!(first[0], ".ds-dns-0");
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
