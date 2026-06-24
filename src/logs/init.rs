use crate::logs::{LogRollingMode, LogTime};
use std::path::Path;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

pub fn init(
    log_directory: impl AsRef<Path>,
    log_file_name: impl AsRef<Path>,
    log_file_rolling: &LogRollingMode,
    log_debug_mode: &bool,
) -> tracing_appender::non_blocking::WorkerGuard {
    let file_appender = log_file_rolling.build(log_directory, log_file_name);
    let (nb, guard) = tracing_appender::non_blocking(file_appender);

    let json_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(nb)
        .with_timer(LogTime)
        .with_current_span(*log_debug_mode)
        .with_span_list(*log_debug_mode)
        .with_target(*log_debug_mode)
        // .with_ansi(false)
        // .with_env_filter("info") //支持RUST_LOG
        .with_line_number(*log_debug_mode)
        .with_file(*log_debug_mode);

    tracing_subscriber::registry()
        .with(EnvFilter::new("info"))
        .with(json_layer)
        .init();

    guard // 返回guard 以确
}
