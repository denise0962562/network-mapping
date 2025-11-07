
pub mod write;
pub mod init;

use tracing_appender::{rolling as import_log_rolling, rolling::RollingFileAppender};
use std::path::Path;
use tracing_subscriber::fmt::time::FormatTime;


pub enum LogRollingMode {
    Daily,
    Hourly,
    Minutely,
    Never,
}

impl LogRollingMode {
    pub fn build(&self, dir: impl AsRef<Path>, name: impl AsRef<Path>) -> RollingFileAppender {
        match self {
            LogRollingMode::Daily => import_log_rolling::daily(dir, name),
            LogRollingMode::Hourly => import_log_rolling::hourly(dir, name),
            LogRollingMode::Minutely => import_log_rolling::minutely(dir, name),
            LogRollingMode::Never => import_log_rolling::never(dir, name)
        }
    }
}

// pub enum LogEventType {
//     ReceivedRequests,
//     BadRequests,
//     AttackRequests,
//     TestRequests,
// }

pub struct LogTime;
///# 用于tracing日志系统的时间格式
///  
/// 使用毫秒级unix时间戳
impl FormatTime for LogTime {
    
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> std::fmt::Result {
        // use crate::get_unix_epoch_ms;
        // let unix_epoch = get_unix_epoch();

        write!(w, "{}", crate::get_unix_epoch_ms())
    }
}