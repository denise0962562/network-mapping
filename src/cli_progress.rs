use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const REPORT_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgressUpdate {
    pub phase: String,
    pub completed: Option<u64>,
    pub total: Option<u64>,
    pub unit: Option<String>,
    pub detail: Option<String>,
}

impl ProgressUpdate {
    pub fn phase(phase: impl Into<String>) -> Self {
        Self {
            phase: phase.into(),
            completed: None,
            total: None,
            unit: None,
            detail: None,
        }
    }

    pub fn count(
        phase: impl Into<String>,
        completed: u64,
        total: Option<u64>,
        unit: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        let detail = detail.into();
        Self {
            phase: phase.into(),
            completed: Some(completed),
            total,
            unit: Some(unit.into()),
            detail: (!detail.is_empty()).then_some(detail),
        }
    }
}

pub trait ProgressReporter: Send + Sync {
    fn is_enabled(&self) -> bool {
        true
    }

    fn report(&self, update: ProgressUpdate);
}

#[derive(Debug, Default)]
pub struct NoopProgressReporter;

impl ProgressReporter for NoopProgressReporter {
    fn is_enabled(&self) -> bool {
        false
    }

    fn report(&self, _update: ProgressUpdate) {}
}

enum ProgressCommand {
    Update(ProgressUpdate),
    Finish(String),
    Fail(String),
    Stop,
}

pub struct CliProgressReporter {
    sender: Sender<ProgressCommand>,
    worker: Mutex<Option<JoinHandle<()>>>,
    closed: AtomicBool,
}

impl CliProgressReporter {
    pub fn new(task: impl Into<String>) -> Self {
        let task = task.into();
        let (sender, receiver) = mpsc::channel();
        let worker = thread::spawn(move || {
            let started_at = Instant::now();
            let mut current: Option<ProgressUpdate> = None;
            let mut next_report_at = Instant::now() + REPORT_INTERVAL;

            loop {
                let wait = next_report_at.saturating_duration_since(Instant::now());
                match receiver.recv_timeout(wait) {
                    Ok(ProgressCommand::Update(update)) => {
                        let phase_changed = current
                            .as_ref()
                            .is_none_or(|previous| previous.phase != update.phase);
                        current = Some(update);
                        if phase_changed {
                            if let Some(update) = current.as_ref() {
                                eprintln!("{}", format_update(&task, update, started_at.elapsed()));
                            }
                            next_report_at = Instant::now() + REPORT_INTERVAL;
                        }
                    }
                    Ok(ProgressCommand::Finish(summary)) => {
                        eprintln!(
                            "[{task}] 完成：{summary}，总耗时 {}",
                            format_duration(started_at.elapsed())
                        );
                        break;
                    }
                    Ok(ProgressCommand::Fail(reason)) => {
                        let context = current
                            .as_ref()
                            .map(|update| format_update(&task, update, started_at.elapsed()))
                            .unwrap_or_else(|| format!("[{task}] 尚未开始"));
                        eprintln!("{context}");
                        eprintln!(
                            "[{task}] 失败：{reason}，总耗时 {}",
                            format_duration(started_at.elapsed())
                        );
                        break;
                    }
                    Ok(ProgressCommand::Stop) | Err(RecvTimeoutError::Disconnected) => break,
                    Err(RecvTimeoutError::Timeout) => {
                        if let Some(update) = current.as_ref() {
                            eprintln!("{}", format_update(&task, update, started_at.elapsed()));
                        }
                        next_report_at = Instant::now() + REPORT_INTERVAL;
                    }
                }
            }
        });
        Self {
            sender,
            worker: Mutex::new(Some(worker)),
            closed: AtomicBool::new(false),
        }
    }

    pub fn finish(&self, summary: impl Into<String>) {
        self.close(ProgressCommand::Finish(summary.into()));
    }

    pub fn fail(&self, reason: impl Into<String>) {
        self.close(ProgressCommand::Fail(reason.into()));
    }

    fn close(&self, command: ProgressCommand) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let _ = self.sender.send(command);
        if let Some(worker) = self
            .worker
            .lock()
            .expect("progress worker lock poisoned")
            .take()
        {
            let _ = worker.join();
        }
    }
}

impl ProgressReporter for CliProgressReporter {
    fn report(&self, update: ProgressUpdate) {
        if !self.closed.load(Ordering::Acquire) {
            let _ = self.sender.send(ProgressCommand::Update(update));
        }
    }
}

impl Drop for CliProgressReporter {
    fn drop(&mut self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            let _ = self.sender.send(ProgressCommand::Stop);
        }
        if let Some(worker) = self
            .worker
            .get_mut()
            .expect("progress worker lock poisoned")
            .take()
        {
            let _ = worker.join();
        }
    }
}

fn format_update(task: &str, update: &ProgressUpdate, elapsed: Duration) -> String {
    let elapsed_text = format_duration(elapsed);
    let detail = update
        .detail
        .as_deref()
        .map(|value| format!("，{value}"))
        .unwrap_or_default();
    match (update.completed, update.total) {
        (Some(completed), Some(total)) => {
            let percentage = if total == 0 {
                100.0
            } else {
                completed as f64 * 100.0 / total as f64
            };
            let unit = update.unit.as_deref().unwrap_or("项");
            let rate = if elapsed.is_zero() {
                0.0
            } else {
                completed as f64 / elapsed.as_secs_f64()
            };
            format!(
                "[{task}] {}：{completed}/{total} {unit} ({percentage:.1}%)，耗时 {elapsed_text}，速度 {rate:.1} {unit}/秒{detail}",
                update.phase
            )
        }
        (Some(completed), None) => {
            let unit = update.unit.as_deref().unwrap_or("项");
            format!(
                "[{task}] {}：已完成 {completed} {unit}，耗时 {elapsed_text}{detail}",
                update.phase
            )
        }
        _ => format!("[{task}] {}，已运行 {elapsed_text}{detail}", update.phase),
    }
}

fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    format!(
        "{:02}:{:02}:{:02}",
        seconds / 3600,
        seconds % 3600 / 60,
        seconds % 60
    )
}

#[cfg(test)]
mod tests {
    use super::{
        CliProgressReporter, NoopProgressReporter, ProgressReporter, ProgressUpdate,
        format_duration, format_update,
    };
    use std::time::Duration;

    #[test]
    fn formats_determinate_progress_with_rate_and_detail() {
        let output = format_update(
            "扫描数据迁移",
            &ProgressUpdate::count("迁移扫描批次", 25, Some(100), "批次", "观察 900/3000 条"),
            Duration::from_secs(10),
        );

        assert_eq!(
            output,
            "[扫描数据迁移] 迁移扫描批次：25/100 批次 (25.0%)，耗时 00:00:10，速度 2.5 批次/秒，观察 900/3000 条"
        );
    }

    #[test]
    fn formats_indeterminate_phase_as_heartbeat() {
        let output = format_update(
            "搜索投影重建",
            &ProgressUpdate::phase("正在执行 PostgreSQL 投影 SQL"),
            Duration::from_secs(65),
        );

        assert_eq!(
            output,
            "[搜索投影重建] 正在执行 PostgreSQL 投影 SQL，已运行 00:01:05"
        );
    }

    #[test]
    fn zero_total_is_complete_without_division_by_zero() {
        let output = format_update(
            "任务",
            &ProgressUpdate::count("处理", 0, Some(0), "项", ""),
            Duration::ZERO,
        );

        assert!(output.contains("0/0 项 (100.0%)"));
        assert!(output.contains("速度 0.0 项/秒"));
    }

    #[test]
    fn formats_long_duration() {
        assert_eq!(format_duration(Duration::from_secs(3661)), "01:01:01");
    }

    #[test]
    fn noop_reporter_disables_optional_progress_queries() {
        assert!(!NoopProgressReporter.is_enabled());
    }

    #[test]
    fn cli_reporter_flushes_updates_before_finishing() {
        let reporter = CliProgressReporter::new("测试任务");
        reporter.report(ProgressUpdate::count(
            "处理",
            1,
            Some(1),
            "项",
            "最后成功 id=1",
        ));
        reporter.finish("1 项");
    }
}
