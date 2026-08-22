use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;
use tokio::process::Command;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

use crate::config::BackupConfig;

#[derive(Clone)]
pub struct BackupManager {
    config: BackupConfig,
    operation_gate: Arc<Semaphore>,
}

#[derive(Debug, Serialize)]
pub struct CommandResult {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl BackupManager {
    pub fn new(config: BackupConfig) -> Self {
        Self {
            config,
            operation_gate: Arc::new(Semaphore::new(1)),
        }
    }

    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn stanza(&self) -> &str {
        &self.config.stanza
    }

    pub fn run_as_user(&self) -> Option<&str> {
        self.config.run_as_user.as_deref()
    }

    pub fn operation_running(&self) -> bool {
        self.operation_gate.available_permits() == 0
    }

    pub fn try_acquire_operation(&self) -> Result<OwnedSemaphorePermit, &'static str> {
        self.operation_gate
            .clone()
            .try_acquire_owned()
            .map_err(|_| "已有备份或检查任务正在运行")
    }

    pub async fn info(&self) -> Result<Value, String> {
        if !self.enabled() {
            return Err("pgBackRest 管理功能未启用".to_owned());
        }
        let result = self
            .execute(
                &["--output=json".to_owned(), "info".to_owned()],
                self.config.command_timeout_seconds.min(30),
            )
            .await?;
        if !result.success {
            return Err(command_failure_message(&result));
        }
        serde_json::from_str(&result.stdout)
            .map_err(|error| format!("pgBackRest 返回了无效 JSON：{error}"))
    }

    pub async fn run_backup(&self, backup_type: &str) -> Result<CommandResult, String> {
        if !matches!(backup_type, "full" | "diff" | "incr") {
            return Err("不支持的备份类型".to_owned());
        }
        self.execute(
            &[format!("--type={backup_type}"), "backup".to_owned()],
            self.config.command_timeout_seconds,
        )
        .await
    }

    pub async fn run_check(&self) -> Result<CommandResult, String> {
        self.execute(&["check".to_owned()], self.config.command_timeout_seconds)
            .await
    }

    async fn execute(
        &self,
        operation_arguments: &[String],
        timeout_seconds: u64,
    ) -> Result<CommandResult, String> {
        if !self.enabled() {
            return Err("pgBackRest 管理功能未启用".to_owned());
        }

        let (program, arguments) = self.command_spec(operation_arguments);
        let mut command = Command::new(program);
        command
            .kill_on_drop(true)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command.args(arguments);

        let output = timeout(Duration::from_secs(timeout_seconds), command.output())
            .await
            .map_err(|_| format!("pgBackRest 命令执行超过 {timeout_seconds} 秒，已终止"))?
            .map_err(|error| format!("无法执行 pgBackRest：{error}"))?;

        Ok(CommandResult {
            success: output.status.success(),
            exit_code: output.status.code(),
            stdout: truncate_output(&output.stdout, self.config.max_output_bytes),
            stderr: truncate_output(&output.stderr, self.config.max_output_bytes),
        })
    }

    fn command_spec(&self, operation_arguments: &[String]) -> (&Path, Vec<String>) {
        let mut arguments = Vec::new();
        let program = if let Some(run_as_user) = self.config.run_as_user.as_deref() {
            arguments.extend([
                "-n".to_owned(),
                "-u".to_owned(),
                run_as_user.to_owned(),
                "--".to_owned(),
                self.config.binary.display().to_string(),
            ]);
            self.config.sudo_binary.as_path()
        } else {
            self.config.binary.as_path()
        };
        append_common_arguments(
            &mut arguments,
            &self.config.stanza,
            self.config.config_file.as_deref(),
        );
        arguments.extend_from_slice(operation_arguments);
        (program, arguments)
    }
}

fn append_common_arguments(arguments: &mut Vec<String>, stanza: &str, config_file: Option<&Path>) {
    if let Some(config_file) = config_file {
        arguments.push(format!("--config={}", config_file.display()));
    }
    arguments.push(format!("--stanza={stanza}"));
}

fn truncate_output(output: &[u8], maximum_bytes: usize) -> String {
    let output = String::from_utf8_lossy(output);
    if output.len() <= maximum_bytes {
        return output.into_owned();
    }

    let mut start = output.len() - maximum_bytes;
    while !output.is_char_boundary(start) {
        start += 1;
    }
    format!("[前部日志因长度限制已省略]\n{}", &output[start..])
}

fn command_failure_message(result: &CommandResult) -> String {
    let detail = if result.stderr.trim().is_empty() {
        result.stdout.trim()
    } else {
        result.stderr.trim()
    };
    if detail.is_empty() {
        format!("pgBackRest 执行失败，退出码：{:?}", result.exit_code)
    } else {
        detail.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::{BackupManager, truncate_output};
    use crate::config::BackupConfig;
    use std::path::{Path, PathBuf};

    #[test]
    fn operation_gate_allows_only_one_mutating_command() {
        let manager = BackupManager::new(BackupConfig::default());
        let permit = manager.try_acquire_operation().expect("first permit");
        assert!(manager.operation_running());
        assert!(manager.try_acquire_operation().is_err());
        drop(permit);
        assert!(!manager.operation_running());
    }

    #[test]
    fn output_truncation_preserves_valid_utf8_tail() {
        let value = "开始-备份完成";
        let truncated = truncate_output(value.as_bytes(), 8);
        assert!(truncated.starts_with("[前部日志因长度限制已省略]"));
        assert!(truncated.ends_with("完成"));
    }

    #[test]
    fn sudo_execution_uses_non_interactive_fixed_run_as_prefix() {
        let manager = BackupManager::new(BackupConfig {
            enabled: true,
            config_file: Some(PathBuf::from("/etc/pgbackrest/pgbackrest.conf")),
            run_as_user: Some("postgres".to_owned()),
            ..BackupConfig::default()
        });
        let (program, arguments) =
            manager.command_spec(&["--type=full".to_owned(), "backup".to_owned()]);

        assert_eq!(program, Path::new("/usr/bin/sudo"));
        assert_eq!(
            arguments,
            [
                "-n",
                "-u",
                "postgres",
                "--",
                "/usr/bin/pgbackrest",
                "--config=/etc/pgbackrest/pgbackrest.conf",
                "--stanza=network_mapping",
                "--type=full",
                "backup",
            ]
        );
    }

    #[test]
    fn direct_execution_remains_available_when_run_as_is_unset() {
        let manager = BackupManager::new(BackupConfig {
            enabled: true,
            ..BackupConfig::default()
        });
        let (program, arguments) =
            manager.command_spec(&["--output=json".to_owned(), "info".to_owned()]);

        assert_eq!(program, Path::new("/usr/bin/pgbackrest"));
        assert_eq!(
            arguments,
            ["--stanza=network_mapping", "--output=json", "info"]
        );
    }

    #[tokio::test]
    async fn run_backup_rejects_non_allowlisted_types_before_execution() {
        let manager = BackupManager::new(BackupConfig {
            enabled: true,
            ..BackupConfig::default()
        });

        let result = manager.run_backup("full --config=/tmp/other.conf").await;

        assert_eq!(result.unwrap_err(), "不支持的备份类型");
    }
}
