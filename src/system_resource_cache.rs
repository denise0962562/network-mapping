//! 进程内系统资源读模型。
//!
//! PostgreSQL 中的 `system_status` 仍是持久化与重启恢复的数据源；HTTP 查询只读本缓存，
//! 从而不会因为扫描结果事务占用连接池而阻塞仪表盘。缓存采用定长保留窗口，避免服务
//! 长时间运行后无界增长。

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, RwLock};

use deadpool_postgres::Pool;
use serde_json::Value;
use tracing::{info, warn};

use crate::SystemResource;

const DETAIL_CAPACITY: usize = 720;
const HISTORY_RETENTION_SECONDS: i64 = 30 * 24 * 60 * 60;
const HYDRATE_PAGE_SIZE: i64 = 10_000;

#[derive(Clone, Copy, Debug)]
struct ResourceSample {
    cpu: Option<f64>,
    ram: Option<f64>,
    disk: Option<f64>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ResourceAggregate {
    pub sample_count: i64,
    pub cpu_avg: Option<f64>,
    pub cpu_max: Option<f64>,
    pub ram_avg: Option<f64>,
    pub ram_max: Option<f64>,
    pub disk_avg: Option<f64>,
    pub disk_max: Option<f64>,
}

#[derive(Default)]
struct CacheInner {
    details: VecDeque<SystemResource>,
    samples: BTreeMap<i64, ResourceSample>,
}

#[derive(Clone, Default)]
pub struct SystemResourceCache {
    inner: Arc<RwLock<CacheInner>>,
}

impl SystemResourceCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// 将一次采集同时写入详细快照和轻量趋势缓存。
    pub fn record(&self, resource: SystemResource) {
        let Some(timestamp) = resource.create_at else {
            return;
        };
        let sample = sample_from_resource(&resource);
        let mut inner = self
            .inner
            .write()
            .unwrap_or_else(|error| error.into_inner());
        inner.details.push_back(resource);
        while inner.details.len() > DETAIL_CAPACITY {
            inner.details.pop_front();
        }
        inner.samples.insert(timestamp, sample);
        prune_samples(&mut inner.samples, timestamp - HISTORY_RETENTION_SECONDS);
    }

    pub fn details(
        &self,
        start_at: Option<i64>,
        end_at: Option<i64>,
        count: i64,
    ) -> Vec<SystemResource> {
        let limit = count.clamp(1, DETAIL_CAPACITY as i64) as usize;
        let inner = self.inner.read().unwrap_or_else(|error| error.into_inner());
        inner
            .details
            .iter()
            .rev()
            .filter(|resource| {
                let timestamp = resource.create_at.unwrap_or_default();
                start_at.is_none_or(|start| timestamp >= start)
                    && end_at.is_none_or(|end| timestamp <= end)
            })
            .take(limit)
            .cloned()
            .collect()
    }

    /// 按请求粒度聚合内存样本。空桶也会返回，保持原 PostgreSQL API 的响应形状。
    pub fn aggregate(
        &self,
        start: i64,
        end: i64,
        bucket_seconds: i64,
    ) -> Vec<(i64, ResourceAggregate)> {
        if start >= end || bucket_seconds <= 0 {
            return Vec::new();
        }
        let first_bucket = (start / bucket_seconds) * bucket_seconds;
        let last_bucket = ((end - 1) / bucket_seconds) * bucket_seconds;
        let mut buckets = BTreeMap::new();
        let mut timestamp = first_bucket;
        while timestamp <= last_bucket {
            buckets.insert(timestamp, AggregateBuilder::default());
            timestamp += bucket_seconds;
        }

        let inner = self.inner.read().unwrap_or_else(|error| error.into_inner());
        for (&sample_time, sample) in inner.samples.range(start..end) {
            let bucket = (sample_time / bucket_seconds) * bucket_seconds;
            if let Some(aggregate) = buckets.get_mut(&bucket) {
                aggregate.push(*sample);
            }
        }
        buckets
            .into_iter()
            .map(|(bucket, aggregate)| (bucket, aggregate.finish()))
            .collect()
    }

    /// 后台分页恢复最近 30 天的轻量样本。分页之间释放连接，避免启动恢复独占连接池。
    pub async fn hydrate_from_database(&self, pool: &Pool) {
        let cutoff = chrono::Utc::now().timestamp() - HISTORY_RETENTION_SECONDS;
        // `system_status.id` 是 PostgreSQL `SERIAL`，其参数类型为 INT4；使用 i64
        // 会在 tokio-postgres 序列化第二个查询参数时失败。
        let mut last_id = 0_i32;
        let mut restored = 0_usize;
        loop {
            let client = match pool.get().await {
                Ok(client) => client,
                Err(error) => {
                    warn!(event = "SystemResourceCacheHydratePoolError", message = %error);
                    return;
                }
            };
            let rows = match client
                .query(
                    "SELECT id, create_time, cpu, ram, disk FROM system_status \
                     WHERE create_time >= $1 AND id > $2 ORDER BY id LIMIT $3",
                    &[&cutoff, &last_id, &HYDRATE_PAGE_SIZE],
                )
                .await
            {
                Ok(rows) => rows,
                Err(error) => {
                    warn!(
                        event = "SystemResourceCacheHydrateQueryError",
                        cutoff_seconds = cutoff,
                        last_id,
                        page_size = HYDRATE_PAGE_SIZE,
                        message = %error,
                        error = ?error,
                        "系统资源缓存恢复查询失败"
                    );
                    return;
                }
            };
            if rows.is_empty() {
                break;
            }
            let page_len = rows.len();
            let mut page = Vec::with_capacity(page_len);
            for row in rows {
                last_id = row.get("id");
                let timestamp = row.get("create_time");
                page.push((
                    timestamp,
                    sample_from_json(row.get("cpu"), row.get("ram"), row.get("disk")),
                ));
            }
            drop(client);
            restored += page.len();
            {
                let mut inner = self
                    .inner
                    .write()
                    .unwrap_or_else(|error| error.into_inner());
                for (timestamp, sample) in page {
                    // `record` 可能已写入更近的实时样本；时间键合并不会覆盖其他周期。
                    inner.samples.entry(timestamp).or_insert(sample);
                }
            }
            if page_len < HYDRATE_PAGE_SIZE as usize {
                break;
            }
            tokio::task::yield_now().await;
        }
        info!(target: "server::startup", restored_samples = restored, "系统资源内存缓存恢复完成");
    }
}

#[derive(Default)]
struct AggregateBuilder {
    sample_count: i64,
    cpu: MetricBuilder,
    ram: MetricBuilder,
    disk: MetricBuilder,
}

impl AggregateBuilder {
    fn push(&mut self, sample: ResourceSample) {
        self.sample_count += 1;
        self.cpu.push(sample.cpu);
        self.ram.push(sample.ram);
        self.disk.push(sample.disk);
    }

    fn finish(self) -> ResourceAggregate {
        let (cpu_avg, cpu_max) = self.cpu.finish();
        let (ram_avg, ram_max) = self.ram.finish();
        let (disk_avg, disk_max) = self.disk.finish();
        ResourceAggregate {
            sample_count: self.sample_count,
            cpu_avg,
            cpu_max,
            ram_avg,
            ram_max,
            disk_avg,
            disk_max,
        }
    }
}

#[derive(Default)]
struct MetricBuilder {
    sum: f64,
    count: u64,
    max: Option<f64>,
}

impl MetricBuilder {
    fn push(&mut self, value: Option<f64>) {
        let Some(value) = value.filter(|value| (0.0..=100.0).contains(value)) else {
            return;
        };
        self.sum += value;
        self.count += 1;
        self.max = Some(self.max.map_or(value, |current| current.max(value)));
    }

    fn finish(self) -> (Option<f64>, Option<f64>) {
        let average = (self.count > 0).then_some(self.sum / self.count as f64);
        (average, self.max)
    }
}

fn sample_from_resource(resource: &SystemResource) -> ResourceSample {
    ResourceSample {
        cpu: Some(resource.cpu.cpu_usage as f64),
        ram: Some(resource.ram.ram_usage as f64),
        disk: (resource.disk.disk_total_space > 0).then(|| {
            resource.disk.disk_total_usage as f64 / resource.disk.disk_total_space as f64 * 100.0
        }),
    }
}

fn sample_from_json(cpu: Value, ram: Value, disk: Value) -> ResourceSample {
    let ram_usage = ram.get("ram_usage").and_then(Value::as_f64).or_else(|| {
        let used = ram.get("used_ram")?.as_f64()?;
        let total = ram.get("total_ram")?.as_f64()?;
        (total > 0.0).then_some(used / total * 100.0)
    });
    let disk_usage = (|| {
        let used = disk.get("disk_total_usage")?.as_f64()?;
        let total = disk.get("disk_total_space")?.as_f64()?;
        (total > 0.0).then_some(used / total * 100.0)
    })();
    ResourceSample {
        cpu: cpu.get("cpu_usage").and_then(Value::as_f64),
        ram: ram_usage,
        disk: disk_usage,
    }
}

fn prune_samples(samples: &mut BTreeMap<i64, ResourceSample>, cutoff: i64) {
    let retained = samples.split_off(&cutoff);
    *samples = retained;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DbResource, SystemCPU, SystemDisk, SystemNetwork, SystemRAM};
    use std::collections::{BTreeMap, HashMap};

    fn resource(timestamp: i64, cpu: f32, ram: f32, disk_used: u64) -> SystemResource {
        SystemResource {
            server_run_time: 1,
            cpu: SystemCPU {
                cpu_usage: cpu,
                cpu: HashMap::new(),
            },
            ram: SystemRAM {
                total_ram: 100,
                used_ram: ram as u64,
                ram_usage: ram,
                total_swap: 0,
                use_swap: 0,
                swap_usage: 0.0,
            },
            disk: SystemDisk {
                disk_total_space: 100,
                disk_total_usage: disk_used,
                disk: HashMap::new(),
            },
            db_postgresql: DbResource::default(),
            network: SystemNetwork {
                net: BTreeMap::new(),
            },
            create_at: Some(timestamp),
        }
    }

    #[test]
    fn newest_details_and_bucket_aggregates_are_read_from_memory() {
        let cache = SystemResourceCache::new();
        cache.record(resource(100, 10.0, 20.0, 30));
        cache.record(resource(105, 30.0, 40.0, 50));

        assert_eq!(cache.details(None, None, 1)[0].create_at, Some(105));
        let points = cache.aggregate(100, 110, 10);
        assert_eq!(points[0].1.sample_count, 2);
        assert_eq!(points[0].1.cpu_avg, Some(20.0));
        assert_eq!(points[0].1.disk_max, Some(50.0));
    }
}
