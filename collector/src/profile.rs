// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use agentsight_capture::analyzers::EvidenceStats;
use clap::ValueEnum;
use serde::Serialize;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

const PROFILE_SCHEMA: &str = "agentsight-profile/v1";
const HEALTH_SCHEMA: &str = "agentsight-capture-health/v1";
const READY_SCHEMA: &str = "agentsight-capture-ready/v1";

#[derive(Clone, Copy, Debug, Default, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CaptureLevel {
    #[default]
    Standard,
    Research,
}

#[derive(Clone, Debug)]
pub(crate) struct ProfileConfig {
    pub(crate) directory: PathBuf,
    pub(crate) profile_id: String,
    pub(crate) scope_id: String,
    pub(crate) capture_level: CaptureLevel,
    pub(crate) ready_file: Option<PathBuf>,
}

impl ProfileConfig {
    pub(crate) fn new(
        directory: PathBuf,
        profile_id: Option<String>,
        scope_id: Option<String>,
        capture_level: CaptureLevel,
        ready_file: Option<PathBuf>,
    ) -> Self {
        Self {
            directory,
            profile_id: profile_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            scope_id: scope_id.unwrap_or_else(|| "default".to_string()),
            capture_level,
            ready_file,
        }
    }

    pub(crate) fn database_path(&self) -> PathBuf {
        self.directory.join("capture.db")
    }

    pub(crate) fn evidence_path(&self) -> PathBuf {
        self.directory.join("system-events.jsonl.zst")
    }

    fn manifest_path(&self) -> PathBuf {
        self.directory.join("profile.json")
    }

    fn health_path(&self) -> PathBuf {
        self.directory.join("health.json")
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ProfileTarget {
    pub(crate) pid: Option<u32>,
    pub(crate) session_id: Option<u32>,
    pub(crate) comm: Option<String>,
    pub(crate) cgroup: Option<String>,
    pub(crate) pid_namespace: Option<String>,
    pub(crate) binary_path: Option<String>,
    pub(crate) tls_binary_only: bool,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ProfileSources {
    pub(crate) tls: bool,
    pub(crate) process: bool,
    pub(crate) stdio: bool,
    pub(crate) system: bool,
    pub(crate) filesystem: bool,
    pub(crate) network: bool,
    pub(crate) signals: bool,
    pub(crate) memory: bool,
    pub(crate) copy_on_write: bool,
    pub(crate) stdio_max_bytes: u32,
    pub(crate) system_interval_seconds: u64,
}

pub(crate) struct ProfileSession {
    config: ProfileConfig,
    manifest: ProfileManifest,
    owner: ProfileOwner,
    finished: bool,
}

#[derive(Clone, Copy)]
struct ProfileOwner {
    uid: u32,
    gid: u32,
}

#[derive(Serialize)]
struct ProfileManifest {
    schema: &'static str,
    profile_id: String,
    scope_id: String,
    capture_level: CaptureLevel,
    status: &'static str,
    started_at_ms: u64,
    ready_at_ms: Option<u64>,
    ended_at_ms: Option<u64>,
    target: ProfileTarget,
    sources: ProfileSources,
    artifacts: ProfileArtifacts,
    runtime: RuntimeMetadata,
}

#[derive(Serialize)]
struct ProfileArtifacts {
    database: &'static str,
    evidence_journal: &'static str,
    health: &'static str,
}

#[derive(Serialize)]
struct RuntimeMetadata {
    agentsight_version: &'static str,
    kernel_release: Option<String>,
    architecture: &'static str,
    collector_pid: u32,
}

#[derive(Serialize)]
struct ReadyRecord<'a> {
    schema: &'static str,
    profile_id: &'a str,
    scope_id: &'a str,
    ready_at_ms: u64,
}

#[derive(Serialize)]
struct HealthRecord<'a> {
    schema: &'static str,
    profile_id: &'a str,
    scope_id: &'a str,
    status: &'a str,
    started_at_ms: u64,
    ready_at_ms: Option<u64>,
    ended_at_ms: u64,
    error: Option<&'a str>,
    evidence: &'a EvidenceStats,
    complete: bool,
}

impl ProfileSession {
    pub(crate) fn start(
        config: ProfileConfig,
        target: ProfileTarget,
        sources: ProfileSources,
    ) -> Result<Self, std::io::Error> {
        std::fs::create_dir_all(&config.directory)?;
        let metadata = std::fs::metadata(&config.directory)?;
        std::fs::set_permissions(&config.directory, std::fs::Permissions::from_mode(0o700))?;
        reset_profile_artifacts(&config)?;
        let session = Self {
            manifest: ProfileManifest {
                schema: PROFILE_SCHEMA,
                profile_id: config.profile_id.clone(),
                scope_id: config.scope_id.clone(),
                capture_level: config.capture_level,
                status: "initializing",
                started_at_ms: current_timestamp_ms(),
                ready_at_ms: None,
                ended_at_ms: None,
                target,
                sources,
                artifacts: ProfileArtifacts {
                    database: "capture.db",
                    evidence_journal: "system-events.jsonl.zst",
                    health: "health.json",
                },
                runtime: RuntimeMetadata {
                    agentsight_version: env!("CARGO_PKG_VERSION"),
                    kernel_release: kernel_release(),
                    architecture: std::env::consts::ARCH,
                    collector_pid: std::process::id(),
                },
            },
            config,
            owner: ProfileOwner {
                uid: metadata.uid(),
                gid: metadata.gid(),
            },
            finished: false,
        };
        session.write_manifest()?;
        Ok(session)
    }

    pub(crate) fn mark_ready(&mut self) -> Result<(), std::io::Error> {
        let ready_at_ms = current_timestamp_ms();
        self.manifest.status = "capturing";
        self.manifest.ready_at_ms = Some(ready_at_ms);
        self.write_manifest()?;
        if let Some(path) = self.config.ready_file.as_deref() {
            write_json(
                path,
                &ReadyRecord {
                    schema: READY_SCHEMA,
                    profile_id: &self.config.profile_id,
                    scope_id: &self.config.scope_id,
                    ready_at_ms,
                },
            )?;
            self.set_artifact_owner(path)?;
        }
        self.set_profile_artifact_owners()?;
        Ok(())
    }

    pub(crate) fn finish(
        mut self,
        stats: EvidenceStats,
        error: Option<&str>,
    ) -> Result<(), std::io::Error> {
        let result = self.finalize(&stats, error);
        self.finished = result.is_ok();
        result
    }

    fn finalize(
        &mut self,
        stats: &EvidenceStats,
        error: Option<&str>,
    ) -> Result<(), std::io::Error> {
        let ended_at_ms = current_timestamp_ms();
        let diagnostic_failure = stats
            .diagnostics_by_type
            .keys()
            .any(|kind| kind == "runner_error" || kind == "runner_parse_error");
        let complete = error.is_none() && stats.write_errors == 0 && !diagnostic_failure;
        self.manifest.status = if error.is_some() {
            "failed"
        } else if complete {
            "completed"
        } else {
            "degraded"
        };
        self.manifest.ended_at_ms = Some(ended_at_ms);
        self.write_manifest()?;
        write_json(
            &self.config.health_path(),
            &HealthRecord {
                schema: HEALTH_SCHEMA,
                profile_id: &self.config.profile_id,
                scope_id: &self.config.scope_id,
                status: self.manifest.status,
                started_at_ms: self.manifest.started_at_ms,
                ready_at_ms: self.manifest.ready_at_ms,
                ended_at_ms,
                error,
                complete,
                evidence: stats,
            },
        )?;
        self.set_profile_artifact_owners()
    }

    fn write_manifest(&self) -> Result<(), std::io::Error> {
        let path = self.config.manifest_path();
        write_json(&path, &self.manifest)?;
        self.set_artifact_owner(&path)
    }

    fn set_profile_artifact_owners(&self) -> Result<(), std::io::Error> {
        [
            self.config.manifest_path(),
            self.config.health_path(),
            self.config.database_path(),
            self.config.database_path().with_extension("db-shm"),
            self.config.database_path().with_extension("db-wal"),
            self.config.evidence_path(),
        ]
        .into_iter()
        .try_for_each(|path| {
            if path.exists() {
                self.set_artifact_owner(&path)?;
            }
            Ok::<(), std::io::Error>(())
        })?;
        if let Some(path) = self.config.ready_file.as_deref()
            && path.exists()
        {
            self.set_artifact_owner(path)?;
        }
        Ok(())
    }

    fn set_artifact_owner(&self, path: &Path) -> Result<(), std::io::Error> {
        if unsafe { libc::geteuid() } != 0 {
            return Ok(());
        }
        std::os::unix::fs::chown(path, Some(self.owner.uid), Some(self.owner.gid))
    }
}

impl Drop for ProfileSession {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let _ = self.finalize(
            &EvidenceStats::default(),
            Some("collector exited before profile finalization"),
        );
    }
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension(format!("tmp-{}", std::process::id()));
    let bytes = serde_json::to_vec_pretty(value).map_err(std::io::Error::other)?;
    std::fs::write(&temp, bytes)?;
    std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(temp, path)
}

fn reset_profile_artifacts(config: &ProfileConfig) -> Result<(), std::io::Error> {
    [
        config.database_path(),
        config.database_path().with_extension("db-shm"),
        config.database_path().with_extension("db-wal"),
        config.evidence_path(),
        config.health_path(),
    ]
    .into_iter()
    .try_for_each(remove_file_if_present)?;
    if let Some(path) = config.ready_file.as_deref() {
        remove_file_if_present(path.to_path_buf())?;
    }
    Ok(())
}

fn remove_file_if_present(path: PathBuf) -> Result<(), std::io::Error> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn kernel_release() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|value| value.trim().to_string())
}

fn current_timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn profile_session_writes_manifest_ready_and_health() {
        let temp = tempfile::tempdir().unwrap();
        let ready = temp.path().join("ready.json");
        let config = ProfileConfig::new(
            temp.path().join("profile"),
            Some("profile-1".to_string()),
            Some("host".to_string()),
            CaptureLevel::Research,
            Some(ready.clone()),
        );
        let mut session = ProfileSession::start(
            config,
            ProfileTarget {
                pid: Some(42),
                session_id: None,
                comm: Some("agent".to_string()),
                cgroup: None,
                pid_namespace: None,
                binary_path: None,
                tls_binary_only: false,
            },
            ProfileSources {
                tls: true,
                process: true,
                stdio: false,
                system: true,
                filesystem: true,
                network: true,
                signals: true,
                memory: true,
                copy_on_write: false,
                stdio_max_bytes: 65_536,
                system_interval_seconds: 2,
            },
        )
        .unwrap();
        session.mark_ready().unwrap();
        session
            .finish(
                EvidenceStats {
                    events_written: 3,
                    events_by_source: BTreeMap::from([("process".to_string(), 3)]),
                    ..EvidenceStats::default()
                },
                None,
            )
            .unwrap();

        assert!(ready.exists());
        let manifest: serde_json::Value = serde_json::from_slice(
            &std::fs::read(temp.path().join("profile/profile.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest["status"], "completed");
        assert_eq!(manifest["target"]["pid"], 42);
        let health: serde_json::Value = serde_json::from_slice(
            &std::fs::read(temp.path().join("profile/health.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(health["complete"], true);
        assert_eq!(health["evidence"]["events_written"], 3);
    }

    #[test]
    fn profile_health_is_degraded_by_parser_diagnostics() {
        let temp = tempfile::tempdir().unwrap();
        let config = ProfileConfig::new(
            temp.path().join("profile"),
            Some("profile-2".to_string()),
            Some("host".to_string()),
            CaptureLevel::Research,
            None,
        );
        let session = ProfileSession::start(
            config,
            ProfileTarget {
                pid: Some(42),
                session_id: None,
                comm: None,
                cgroup: None,
                pid_namespace: None,
                binary_path: None,
                tls_binary_only: false,
            },
            ProfileSources {
                tls: false,
                process: true,
                stdio: false,
                system: false,
                filesystem: true,
                network: true,
                signals: true,
                memory: true,
                copy_on_write: false,
                stdio_max_bytes: 65_536,
                system_interval_seconds: 2,
            },
        )
        .unwrap();
        session
            .finish(
                EvidenceStats {
                    diagnostics_by_type: BTreeMap::from([("runner_parse_error".to_string(), 1)]),
                    ..EvidenceStats::default()
                },
                None,
            )
            .unwrap();

        let health: serde_json::Value = serde_json::from_slice(
            &std::fs::read(temp.path().join("profile/health.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(health["status"], "degraded");
        assert_eq!(health["complete"], false);
    }

    #[test]
    fn dropped_profile_records_failed_finalization() {
        let temp = tempfile::tempdir().unwrap();
        let config = ProfileConfig::new(
            temp.path().join("profile"),
            Some("profile-3".to_string()),
            Some("host".to_string()),
            CaptureLevel::Research,
            None,
        );
        drop(
            ProfileSession::start(
                config,
                ProfileTarget {
                    pid: Some(42),
                    session_id: None,
                    comm: None,
                    cgroup: None,
                    pid_namespace: None,
                    binary_path: None,
                    tls_binary_only: false,
                },
                ProfileSources {
                    tls: false,
                    process: true,
                    stdio: false,
                    system: false,
                    filesystem: true,
                    network: true,
                    signals: true,
                    memory: true,
                    copy_on_write: false,
                    stdio_max_bytes: 65_536,
                    system_interval_seconds: 2,
                },
            )
            .unwrap(),
        );

        let health: serde_json::Value = serde_json::from_slice(
            &std::fs::read(temp.path().join("profile/health.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(health["status"], "failed");
        assert_eq!(health["complete"], false);
    }

    #[test]
    fn profile_start_removes_stale_capture_artifacts_and_readiness() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("profile");
        std::fs::create_dir_all(&directory).unwrap();
        for name in [
            "capture.db",
            "capture.db-shm",
            "capture.db-wal",
            "system-events.jsonl.zst",
            "health.json",
            "ready.json",
        ] {
            std::fs::write(directory.join(name), b"stale").unwrap();
        }
        let config = ProfileConfig::new(
            directory.clone(),
            Some("profile-reused".to_string()),
            Some("host".to_string()),
            CaptureLevel::Research,
            Some(directory.join("ready.json")),
        );
        let session = ProfileSession::start(
            config,
            ProfileTarget {
                pid: Some(42),
                session_id: None,
                comm: None,
                cgroup: None,
                pid_namespace: None,
                binary_path: None,
                tls_binary_only: false,
            },
            ProfileSources {
                tls: false,
                process: true,
                stdio: false,
                system: true,
                filesystem: true,
                network: true,
                signals: true,
                memory: true,
                copy_on_write: false,
                stdio_max_bytes: 65_536,
                system_interval_seconds: 2,
            },
        )
        .unwrap();

        assert!(directory.join("profile.json").exists());
        for name in [
            "capture.db",
            "capture.db-shm",
            "capture.db-wal",
            "system-events.jsonl.zst",
            "health.json",
            "ready.json",
        ] {
            assert!(!directory.join(name).exists());
        }
        drop(session);
    }

    #[test]
    fn root_profile_writer_preserves_preexisting_directory_owner() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("profile");
        std::fs::create_dir_all(&directory).unwrap();
        std::os::unix::fs::chown(&directory, Some(12_345), Some(12_346)).unwrap();
        let ready = directory.join("ready.json");
        let config = ProfileConfig::new(
            directory.clone(),
            Some("profile-owner".to_string()),
            Some("task-container".to_string()),
            CaptureLevel::Research,
            Some(ready.clone()),
        );
        let mut session = ProfileSession::start(
            config,
            ProfileTarget {
                pid: None,
                session_id: None,
                comm: None,
                cgroup: None,
                pid_namespace: Some("/proc/42/ns/pid".to_string()),
                binary_path: None,
                tls_binary_only: false,
            },
            ProfileSources {
                tls: false,
                process: true,
                stdio: false,
                system: true,
                filesystem: true,
                network: true,
                signals: true,
                memory: true,
                copy_on_write: false,
                stdio_max_bytes: 65_536,
                system_interval_seconds: 2,
            },
        )
        .unwrap();
        session.mark_ready().unwrap();

        for path in [directory.join("profile.json"), ready] {
            let metadata = std::fs::metadata(path).unwrap();
            assert_eq!(metadata.uid(), 12_345);
            assert_eq!(metadata.gid(), 12_346);
        }
        drop(session);
    }
}
