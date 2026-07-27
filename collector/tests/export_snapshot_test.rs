// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use std::process::{Command, Output};

fn fixture_session_path(
    agent: &str,
    temp: &tempfile::TempDir,
    file_name: &str,
) -> std::path::PathBuf {
    agent_session::fixture_session_path(agent, temp.path())
        .unwrap()
        .with_file_name(file_name)
}

fn agentsight_output(args: &[&str]) -> Output {
    agentsight_output_with_env(args, &[])
}

fn agentsight_output_with_env(args: &[&str], envs: &[(&str, &std::ffi::OsStr)]) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_agentsight"))
        .args(args)
        .envs(envs.iter().copied())
        .output()
        .expect("agentsight command should run");
    assert!(
        output.status.success(),
        "agentsight {:?} failed\nstdout:\n{}\nstderr:\n{}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn agentsight_stdout(args: &[&str]) -> String {
    String::from_utf8(agentsight_output(args).stdout).expect("stdout should be UTF-8")
}

fn agentsight_stdout_with_env(args: &[&str], envs: &[(&str, &std::ffi::OsStr)]) -> String {
    String::from_utf8(agentsight_output_with_env(args, envs).stdout)
        .expect("stdout should be UTF-8")
}

#[test]
fn top_level_help_surfaces_perf_strace_flow() {
    let help = agentsight_stdout(&["--help"]);
    assert!(
        help.contains("top/record/report for AI agent runs"),
        "{help}"
    );
    assert!(help.contains("top"), "{help}");
    assert!(help.contains("record"), "{help}");
    assert!(help.contains("report"), "{help}");
    assert!(help.contains("prompts"), "{help}");
    assert!(help.contains("list"), "{help}");
}

#[test]
fn agent_native_summary_reads_codex_session_jsonl() {
    let temp = tempfile::tempdir().expect("tempdir");
    let session_path =
        fixture_session_path(agent_session::AGENT_CODEX, &temp, "rollout-test.jsonl");
    std::fs::create_dir_all(session_path.parent().unwrap()).expect("session dir");
    std::fs::write(
        session_path,
        concat!(
            "{\"type\":\"turn_context\",\"payload\":{\"model\":\"gpt-5.5\"}}\n",
            "{\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":11,\"output_tokens\":4,\"total_tokens\":15}}}}\n",
            "{\"type\":\"response_item\",\"payload\":{\"type\":\"function_call\",\"name\":\"shell\"}}\n",
        ),
    )
    .expect("codex session");

    let summary =
        agentsight_stdout_with_env(&["report", "--local"], &[("HOME", temp.path().as_os_str())]);
    assert!(
        summary.contains("agent_native_session session"),
        "{summary}"
    );
    assert!(summary.contains("gpt-5.5"), "{summary}");
    assert!(summary.contains("15 tokens"), "{summary}");
    assert!(summary.contains("shell(1)"), "{summary}");
}

#[test]
fn top_without_db_uses_live_process_view() {
    let top = agentsight_stdout(&["top", "--once"]);
    assert!(top.contains("AgentSight top -"), "{top}");
    assert!(top.contains("live sessions"), "{top}");
    assert!(top.contains("SESSION"), "{top}");
    assert!(top.contains("AGENT"), "{top}");
    assert!(top.contains("STATE"), "{top}");
    assert!(top.contains("AGE"), "{top}");
    assert!(top.contains("ACTIVITY"), "{top}");
    assert!(top.contains("EVIDENCE"), "{top}");
}

#[test]
fn top_discovers_agent_native_sessions() {
    let temp = tempfile::tempdir().expect("tempdir");
    let session_path =
        fixture_session_path(agent_session::AGENT_CODEX, &temp, "rollout-test.jsonl");
    std::fs::create_dir_all(session_path.parent().unwrap()).expect("session dir");
    std::fs::write(
        session_path,
        concat!(
            "{\"timestamp\":\"2026-07-12T10:00:00Z\",\"type\":\"turn_context\",\"payload\":{\"model\":\"gpt-5.5\"}}\n",
            "{\"timestamp\":\"2026-07-12T10:00:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":11,\"output_tokens\":4,\"total_tokens\":15}}}}\n",
            "{\"type\":\"response_item\",\"payload\":{\"type\":\"function_call\",\"name\":\"shell\"}}\n",
            "{\"timestamp\":\"2026-07-12T10:00:00Z\",\"type\":\"message\",\"content\":\"fix the test\"}\n",
        ),
    )
    .expect("codex session");

    let tz = std::ffi::OsStr::new("UTC");
    let top = agentsight_stdout_with_env(
        &["top", "--once", "--limit", "20"],
        &[("HOME", temp.path().as_os_str()), ("TZ", tz)],
    );
    assert!(top.contains("live sessions"), "{top}");
    assert!(top.contains("codex:rollout-test"), "{top}");
    assert!(top.contains("TOKENS"), "{top}");
    assert!(top.contains("ACTIVITY"), "{top}");
    assert!(top.contains("LAST MSG"), "{top}");
    assert!(top.contains("session tokens: 15"), "{top}");
    assert!(top.contains("15"), "{top}");
    assert!(top.contains("10:00:00"), "{top}");
    assert!(top.contains("1 tool"), "{top}");
    assert!(top.contains("fix the test"), "{top}");
}

#[test]
fn top_reads_active_claude_local_session_model_and_tokens() {
    let temp = tempfile::tempdir().expect("tempdir");
    let session_path =
        fixture_session_path(agent_session::AGENT_CLAUDE, &temp, "claude-active.jsonl");
    std::fs::create_dir_all(session_path.parent().unwrap()).expect("session dir");
    std::fs::write(
        session_path,
        concat!(
            "{\"type\":\"user\",\"sessionId\":\"claude-active\",\"message\":{\"content\":\"inspect the trace\"}}\n",
            "{\"type\":\"assistant\",\"sessionId\":\"claude-active\",\"requestId\":\"req_1\",\"message\":{\"model\":\"claude-opus-4-6\",\"content\":[{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"Bash\",\"input\":{\"command\":\"true\"}}],\"usage\":{\"input_tokens\":3,\"cache_creation_input_tokens\":5,\"cache_read_input_tokens\":7,\"output_tokens\":11}}}\n",
            "{\"type\":\"assistant\",\"sessionId\":\"claude-active\",\"requestId\":\"req_1\",\"message\":{\"model\":\"claude-opus-4-6\",\"content\":[{\"type\":\"text\",\"text\":\"done\"}],\"usage\":{\"input_tokens\":3,\"cache_creation_input_tokens\":5,\"cache_read_input_tokens\":7,\"output_tokens\":11}}}\n",
        ),
    )
    .expect("claude session");

    let top = agentsight_stdout_with_env(
        &["top", "--once", "--limit", "20"],
        &[("HOME", temp.path().as_os_str())],
    );
    assert!(top.contains("claude:"), "{top}");
    assert!(top.contains("inspect the trace"), "{top}");
    assert!(top.contains("claude-opus-4-6"), "{top}");
    assert!(top.contains("26"), "{top}");
    assert!(top.contains("1 tool"), "{top}");
}

#[test]
fn report_exports_one_scope_aware_snapshot_for_multi_scope_profile() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_profile_source(temp.path(), "host", 1_000);
    write_profile_source(temp.path(), "task-container", 2_000);
    let output = temp.path().join("snapshot.json");

    agentsight_output(&[
        "report",
        "--profile-dir",
        temp.path().to_str().unwrap(),
        "export",
        "--output",
        output.to_str().unwrap(),
    ]);

    let snapshot: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
    assert_eq!(
        snapshot["source_scopes"],
        serde_json::json!(["host", "task-container"])
    );
    let rows = snapshot["audit_events"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["id"], "same-id");
    assert_eq!(rows[1]["id"], "same-id");
    assert_eq!(rows[0]["scope_id"], "host");
    assert_eq!(rows[1]["scope_id"], "task-container");
}

#[test]
fn report_summary_uses_top_level_multi_scope_profile() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_profile_source(temp.path(), "host", 1_000);
    write_profile_source(temp.path(), "task-container", 2_000);

    let output = agentsight_output(&[
        "report",
        "--profile-dir",
        temp.path().to_str().unwrap(),
        "summary",
    ]);
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");

    assert!(stdout.contains("scopes host, task-container"), "{stdout}");
    assert!(!stderr.contains("using local agent sessions"), "{stderr}");
}

fn write_profile_source(root: &std::path::Path, scope_id: &str, timestamp_ms: u64) {
    let directory = root.join("sources").join(scope_id);
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join("profile.json"),
        serde_json::to_vec(&serde_json::json!({
            "profile_id": "profile-1",
            "scope_id": scope_id,
        }))
        .unwrap(),
    )
    .unwrap();
    let database = rusqlite::Connection::open(directory.join("capture.db")).unwrap();
    database
        .execute_batch(
            "CREATE TABLE audit_events (
                id TEXT PRIMARY KEY,
                timestamp_ms INTEGER NOT NULL,
                audit_type TEXT NOT NULL,
                pid INTEGER,
                comm TEXT,
                subject TEXT,
                action TEXT,
                target TEXT,
                status TEXT,
                summary TEXT,
                details_json TEXT NOT NULL DEFAULT '{}'
            );",
        )
        .unwrap();
    database
        .execute(
            "INSERT INTO audit_events (
                id, timestamp_ms, audit_type, pid, comm, action, target, status, details_json
             ) VALUES ('same-id', ?1, 'process', 42, 'agent', 'exec', '/bin/agent', 'observed', '{}')",
            [timestamp_ms as i64],
        )
        .unwrap();
}
