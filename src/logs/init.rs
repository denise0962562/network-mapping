use crate::logs::{ConsoleTime, LogRollingMode, LogTime};
use std::{io::IsTerminal, path::Path};
use tracing_subscriber::{EnvFilter, Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt};

pub fn init(
    log_directory: impl AsRef<Path>,
    log_file_name: impl AsRef<Path>,
    log_file_rolling: &LogRollingMode,
    log_debug_mode: &bool,
    terminal_verbose: bool,
) -> tracing_appender::non_blocking::WorkerGuard {
    let file_appender = log_file_rolling.build(log_directory, log_file_name);
    let (nb, guard) = tracing_appender::non_blocking(file_appender);

    let default_level = if *log_debug_mode { "debug" } else { "info" };
    let file_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));
    let console_filter = if terminal_verbose {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level))
    } else {
        EnvFilter::new("warn,server::startup=info")
    };

    let console_layer = fmt::layer()
        .compact()
        .with_writer(std::io::stdout)
        .with_timer(ConsoleTime)
        .with_ansi(std::io::stdout().is_terminal())
        .with_target(*log_debug_mode)
        .with_line_number(*log_debug_mode)
        .with_file(*log_debug_mode)
        .with_filter(console_filter);

    let json_layer = fmt::layer()
        .json()
        .with_writer(nb)
        .with_timer(LogTime)
        .with_current_span(*log_debug_mode)
        .with_span_list(*log_debug_mode)
        .with_target(*log_debug_mode)
        // .with_ansi(false)
        // .with_env_filter("info") //支持RUST_LOG
        .with_line_number(*log_debug_mode)
        .with_file(*log_debug_mode)
        .with_filter(file_filter);

    tracing_subscriber::registry()
        .with(console_layer)
        .with(json_layer)
        .init();

    guard // 返回guard 以确
}
