use super::detector::encode_path_for_matching;
use super::source::{
    CliActivity, DetectedSession, DetectionDiagnostics, SessionDetectorError, SessionKind,
    SessionSource,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use wait_timeout::ChildExt;

#[derive(Deserialize, Debug)]
struct CliAgent {
    pid: u32,
    cwd: PathBuf,
    // `kind` was added alongside background-pinned sessions in CC 2.1.147.
    // 2.1.145–146 emit `claude agents --json` without it; default to "interactive".
    #[serde(default = "default_kind")]
    kind: String,
    #[serde(rename = "startedAt")]
    started_at: i64,
    #[serde(rename = "sessionId")]
    session_id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct PidSessionMeta {
    #[serde(default)]
    pid: Option<u32>,
    cwd: PathBuf,
    #[serde(default = "default_kind")]
    kind: String,
    #[serde(rename = "startedAt")]
    started_at: i64,
    #[serde(rename = "sessionId")]
    session_id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

fn default_kind() -> String {
    "interactive".to_string()
}

fn session_kind(kind: &str) -> SessionKind {
    match kind {
        "interactive" => SessionKind::Interactive,
        "background" => SessionKind::Background,
        _ => SessionKind::Unknown,
    }
}

fn cli_activity(status: Option<&str>) -> Option<CliActivity> {
    match status {
        Some("busy") => Some(CliActivity::Busy),
        Some("idle") => Some(CliActivity::Idle),
        _ => None,
    }
}

pub struct CliSessionSource {
    claude_bin: PathBuf,
    path_cache: HashMap<String, PathBuf>,
}

impl CliSessionSource {
    pub fn new() -> Self {
        // Relies on PATH lookup at spawn time. We don't pull in `which` as a
        // direct dep just for this — the probe already verified `claude` is on PATH.
        Self {
            claude_bin: PathBuf::from("claude"),
            path_cache: HashMap::new(),
        }
    }

    fn project_path_for_session(&mut self, cwd: &Path, session_id: &str) -> PathBuf {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"));
        lookup_with_cache(&home, &mut self.path_cache, cwd, session_id)
    }

    fn map_agent_to_session(&mut self, a: CliAgent) -> DetectedSession {
        let project_path = self.project_path_for_session(&a.cwd, &a.session_id);
        detected_session_from_parts(
            a.pid,
            a.cwd,
            project_path,
            a.kind,
            a.started_at,
            a.session_id,
            a.name,
            a.status,
        )
    }
}

impl SessionSource for CliSessionSource {
    fn detect(
        &mut self,
    ) -> Result<(Vec<DetectedSession>, DetectionDiagnostics), SessionDetectorError> {
        let mut child = Command::new(&self.claude_bin)
            .args(["agents", "--json"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| SessionDetectorError::CliFailed(format!("spawn: {e}")))?;

        // Drain stdout on a background thread to avoid pipe-buffer deadlock
        // when the child writes more than the OS pipe buffer (typically 64KB).
        // The reader exits naturally when the child closes stdout (on exit or kill).
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| SessionDetectorError::CliFailed("stdout pipe missing".to_string()))?;
        let reader = std::thread::spawn(move || {
            let mut stdout = stdout;
            let mut buf = Vec::new();
            let _ = stdout.read_to_end(&mut buf);
            buf
        });

        let timeout = Duration::from_secs(2);
        let status = match child
            .wait_timeout(timeout)
            .map_err(|e| SessionDetectorError::CliFailed(format!("wait: {e}")))?
        {
            Some(s) => s,
            None => {
                let _ = child.kill();
                // Reap to avoid leaving a zombie on Unix; then join the reader
                // (kill closes the pipe so the reader exits naturally).
                let _ = child.wait();
                let _ = reader.join();
                return Err(SessionDetectorError::Timeout(timeout.as_millis()));
            }
        };

        let buf = reader
            .join()
            .map_err(|_| SessionDetectorError::CliFailed("stdout reader panicked".to_string()))?;

        if !status.success() {
            return Err(SessionDetectorError::CliFailed(format!(
                "exit code {status:?}"
            )));
        }

        let agents: Vec<CliAgent> =
            serde_json::from_slice(&buf).map_err(|e| SessionDetectorError::Parse(e.to_string()))?;

        // Filter out known non-monitorable SDK entrypoints, but keep Claude Code
        // surfaces that still write project JSONLs (CLI and VS Code). The per-pid
        // metadata at ~/.claude/sessions/<pid>.json carries `entrypoint`. If the
        // file is missing or unreadable, keep the agent for older CC versions.
        let mut seen_session_ids = HashSet::new();
        let mut sessions: Vec<DetectedSession> = agents
            .into_iter()
            .filter(|a| is_monitorable_entrypoint(a.pid))
            .map(|a| {
                seen_session_ids.insert(a.session_id.clone());
                self.map_agent_to_session(a)
            })
            .collect();

        // `claude agents --json` has returned an empty list for live VS Code
        // sessions on some Claude Code builds. Recover those from the authoritative
        // pid metadata, but only when the process is alive and its JSONL exists.
        if let Some(home) = dirs::home_dir() {
            sessions.extend(metadata_sessions_under(
                &home,
                &mut self.path_cache,
                &seen_session_ids,
                process_is_alive,
            ));
        }

        Ok((sessions, DetectionDiagnostics::default()))
    }

    fn backend_name(&self) -> &'static str {
        "cli"
    }
}

/// Returns true if the agent at this pid is a Claude Code surface c9watch can
/// monitor. Reads `~/.claude/sessions/<pid>.json` and inspects `entrypoint`.
/// Missing/unreadable file -> keep (older CC builds didn't write this metadata;
/// better to over-report than drop real CLIs).
fn is_monitorable_entrypoint(pid: u32) -> bool {
    match dirs::home_dir() {
        Some(home) => is_monitorable_entrypoint_under(&home, pid),
        None => true,
    }
}

fn is_monitorable_entrypoint_under(home: &Path, pid: u32) -> bool {
    let path = home
        .join(".claude")
        .join("sessions")
        .join(format!("{pid}.json"));
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return true,
    };
    let value: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return true,
    };
    match value.get("entrypoint").and_then(|v| v.as_str()) {
        Some("sdk-ts" | "sdk-py") => false,
        Some("cli" | "claude-vscode") => true,
        Some(_) => true,
        None => true,
    }
}

fn detected_session_from_parts(
    pid: u32,
    cwd: PathBuf,
    project_path: PathBuf,
    kind: String,
    started_at: i64,
    session_id: String,
    name: Option<String>,
    status: Option<String>,
) -> DetectedSession {
    let project_name = cwd
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();

    DetectedSession {
        pid,
        project_name,
        session_id: Some(session_id),
        project_path,
        kind: session_kind(&kind),
        started_at_ms: Some(started_at),
        official_name: name,
        cli_activity: cli_activity(status.as_deref()),
        cwd,
    }
}

fn metadata_sessions_under(
    home: &Path,
    path_cache: &mut HashMap<String, PathBuf>,
    already_seen_session_ids: &HashSet<String>,
    pid_is_alive: impl Fn(u32) -> bool,
) -> Vec<DetectedSession> {
    let sessions_dir = home.join(".claude").join("sessions");
    let Ok(entries) = std::fs::read_dir(&sessions_dir) else {
        return Vec::new();
    };

    let mut seen = already_seen_session_ids.clone();
    let mut sessions = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() || path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }

        let Some(file_pid) = path
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };

        if !pid_is_alive(file_pid) || !is_monitorable_entrypoint_under(home, file_pid) {
            continue;
        }

        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(meta) = serde_json::from_str::<PidSessionMeta>(&raw) else {
            continue;
        };

        let pid = meta.pid.unwrap_or(file_pid);
        if pid != file_pid || !seen.insert(meta.session_id.clone()) {
            continue;
        }

        let Some(project_path) = resolve_project_path_under(home, &meta.cwd, &meta.session_id)
        else {
            continue;
        };
        path_cache.insert(meta.session_id.clone(), project_path.clone());

        sessions.push(detected_session_from_parts(
            pid,
            meta.cwd,
            project_path,
            meta.kind,
            meta.started_at,
            meta.session_id,
            meta.name,
            meta.status,
        ));
    }

    sessions
}

#[cfg(unix)]
fn process_is_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if result == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(not(unix))]
fn process_is_alive(pid: u32) -> bool {
    pid != 0
}

/// Stateless resolver used by both production code (with real `home_dir()`) and
/// tests (with a tempdir as `home`). Encoded-cwd fast-path then directory scan.
fn resolve_project_path_under(home: &Path, cwd: &Path, session_id: &str) -> Option<PathBuf> {
    let projects_root = home.join(".claude").join("projects");
    let encoded = encode_path_for_matching(&cwd.to_string_lossy());
    let fast = projects_root.join(&encoded);
    if fast.join(format!("{session_id}.jsonl")).is_file() {
        return Some(fast);
    }
    let entries = std::fs::read_dir(&projects_root).ok()?;
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() && p.join(format!("{session_id}.jsonl")).is_file() {
            return Some(p);
        }
    }
    None
}

fn fallback_path_under(home: &Path, cwd: &Path) -> PathBuf {
    let encoded = encode_path_for_matching(&cwd.to_string_lossy());
    home.join(".claude").join("projects").join(encoded)
}

/// Cache-aware resolver. Verifies stale cache entries (jsonl gone) and re-resolves.
/// Falls back to `fallback_path_under` when resolution fails so enrichment has SOMETHING
/// to try (and skip cleanly when JSONL never appears).
fn lookup_with_cache(
    home: &Path,
    cache: &mut HashMap<String, PathBuf>,
    cwd: &Path,
    session_id: &str,
) -> PathBuf {
    if let Some(cached) = cache.get(session_id).cloned() {
        if cached.join(format!("{session_id}.jsonl")).is_file() {
            return cached;
        }
        cache.remove(session_id);
    }
    if let Some(resolved) = resolve_project_path_under(home, cwd, session_id) {
        cache.insert(session_id.to_string(), resolved.clone());
        return resolved;
    }
    fallback_path_under(home, cwd)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_schema_json() -> &'static str {
        r#"[
          {"pid":1,"cwd":"/tmp/a","kind":"interactive","startedAt":100,"sessionId":"sid-a","status":"busy"},
          {"pid":2,"cwd":"/tmp/b","kind":"background","startedAt":200,"sessionId":"sid-b","name":"my-bg","status":"idle"}
        ]"#
    }

    #[test]
    fn parse_cli_output_full_schema() {
        let agents: Vec<CliAgent> = serde_json::from_str(full_schema_json()).unwrap();
        assert_eq!(agents.len(), 2);
        assert_eq!(agents[0].pid, 1);
        assert_eq!(agents[0].session_id, "sid-a");
        assert_eq!(agents[1].name.as_deref(), Some("my-bg"));
    }

    #[test]
    fn parse_cli_output_missing_status_yields_none_in_mapping() {
        let json = r#"[{"pid":1,"cwd":"/tmp","kind":"interactive","startedAt":1,"sessionId":"x"}]"#;
        let agents: Vec<CliAgent> = serde_json::from_str(json).unwrap();
        assert!(agents[0].status.is_none());
        let mapped_activity = match agents[0].status.as_deref() {
            Some("busy") => Some(CliActivity::Busy),
            Some("idle") => Some(CliActivity::Idle),
            _ => None,
        };
        assert!(mapped_activity.is_none());
    }

    #[test]
    fn parse_cli_output_busy_yields_some_busy() {
        let json = r#"[{"pid":1,"cwd":"/tmp","kind":"interactive","startedAt":1,"sessionId":"x","status":"busy"}]"#;
        let agents: Vec<CliAgent> = serde_json::from_str(json).unwrap();
        let mapped = match agents[0].status.as_deref() {
            Some("busy") => Some(CliActivity::Busy),
            Some("idle") => Some(CliActivity::Idle),
            _ => None,
        };
        assert_eq!(mapped, Some(CliActivity::Busy));
    }

    #[test]
    fn parse_cli_output_unknown_status_yields_none() {
        let json = r#"[{"pid":1,"cwd":"/tmp","kind":"interactive","startedAt":1,"sessionId":"x","status":"on_fire"}]"#;
        let agents: Vec<CliAgent> = serde_json::from_str(json).unwrap();
        let mapped = match agents[0].status.as_deref() {
            Some("busy") => Some(CliActivity::Busy),
            Some("idle") => Some(CliActivity::Idle),
            _ => None,
        };
        assert!(mapped.is_none());
    }

    #[test]
    fn parse_cli_output_unknown_kind_yields_unknown() {
        let json = r#"[{"pid":1,"cwd":"/tmp","kind":"chimera","startedAt":1,"sessionId":"x"}]"#;
        let agents: Vec<CliAgent> = serde_json::from_str(json).unwrap();
        let mapped_kind = match agents[0].kind.as_str() {
            "interactive" => SessionKind::Interactive,
            "background" => SessionKind::Background,
            _ => SessionKind::Unknown,
        };
        assert_eq!(mapped_kind, SessionKind::Unknown);
    }

    #[test]
    fn parse_cli_output_missing_kind_defaults_to_interactive() {
        // CC 2.1.145–146 emit `claude agents --json` without the `kind` field.
        let json = r#"[{"pid":1,"cwd":"/tmp","startedAt":1,"sessionId":"x"}]"#;
        let agents: Vec<CliAgent> = serde_json::from_str(json).unwrap();
        assert_eq!(agents[0].kind, "interactive");
    }

    #[test]
    fn parse_cli_output_empty_array() {
        let agents: Vec<CliAgent> = serde_json::from_str("[]").unwrap();
        assert!(agents.is_empty());
    }

    #[test]
    fn parse_cli_output_malformed_returns_err() {
        let result: Result<Vec<CliAgent>, _> = serde_json::from_str("not json");
        assert!(result.is_err());
    }

    #[test]
    fn resolve_project_path_finds_via_fast_path() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let cwd = PathBuf::from("/Users/test/proj");
        let session_id = "sess-fast";
        let encoded = encode_path_for_matching(&cwd.to_string_lossy());
        let proj_dir = home.join(".claude").join("projects").join(&encoded);
        std::fs::create_dir_all(&proj_dir).unwrap();
        std::fs::write(proj_dir.join(format!("{session_id}.jsonl")), b"").unwrap();

        let result = resolve_project_path_under(home, &cwd, session_id);
        assert_eq!(result.as_deref(), Some(proj_dir.as_path()));
    }

    #[test]
    fn resolve_project_path_falls_back_to_scan_when_encoding_mismatches() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let cwd = PathBuf::from("/Users/test/proj");
        let session_id = "sess-scan";
        let wrong_dir = home
            .join(".claude")
            .join("projects")
            .join("totally-different-dir");
        std::fs::create_dir_all(&wrong_dir).unwrap();
        std::fs::write(wrong_dir.join(format!("{session_id}.jsonl")), b"").unwrap();

        let result = resolve_project_path_under(home, &cwd, session_id);
        assert_eq!(result.as_deref(), Some(wrong_dir.as_path()));
    }

    #[test]
    fn resolve_project_path_returns_none_when_jsonl_missing_everywhere() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let cwd = PathBuf::from("/Users/test/proj");
        let result = resolve_project_path_under(home, &cwd, "absent");
        assert!(result.is_none());
    }

    #[test]
    fn path_cache_returns_cached_value_when_jsonl_still_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let cwd = PathBuf::from("/Users/test/proj");
        let session_id = "cache-hit";
        let encoded = encode_path_for_matching(&cwd.to_string_lossy());
        let proj_dir = home.join(".claude").join("projects").join(&encoded);
        std::fs::create_dir_all(&proj_dir).unwrap();
        std::fs::write(proj_dir.join(format!("{session_id}.jsonl")), b"").unwrap();

        let mut cache: HashMap<String, PathBuf> = HashMap::new();
        cache.insert(session_id.to_string(), proj_dir.clone());

        let result = lookup_with_cache(home, &mut cache, &cwd, session_id);
        assert_eq!(result, proj_dir);
        assert_eq!(cache.len(), 1, "cache size unchanged on hit");
    }

    fn write_session_meta(home: &Path, pid: u32, entrypoint: Option<&str>) {
        let dir = home.join(".claude").join("sessions");
        std::fs::create_dir_all(&dir).unwrap();
        let body = match entrypoint {
            Some(ep) => format!(r#"{{"pid":{pid},"entrypoint":"{ep}"}}"#),
            None => format!(r#"{{"pid":{pid}}}"#),
        };
        std::fs::write(dir.join(format!("{pid}.json")), body).unwrap();
    }

    #[test]
    fn entrypoint_filter_keeps_cli() {
        let tmp = tempfile::tempdir().unwrap();
        write_session_meta(tmp.path(), 1, Some("cli"));
        assert!(is_monitorable_entrypoint_under(tmp.path(), 1));
    }

    #[test]
    fn entrypoint_filter_keeps_claude_vscode() {
        let tmp = tempfile::tempdir().unwrap();
        write_session_meta(tmp.path(), 6, Some("claude-vscode"));
        assert!(is_monitorable_entrypoint_under(tmp.path(), 6));
    }

    #[test]
    fn entrypoint_filter_drops_sdk_ts() {
        let tmp = tempfile::tempdir().unwrap();
        write_session_meta(tmp.path(), 2, Some("sdk-ts"));
        assert!(!is_monitorable_entrypoint_under(tmp.path(), 2));
    }

    #[test]
    fn entrypoint_filter_drops_sdk_py() {
        let tmp = tempfile::tempdir().unwrap();
        write_session_meta(tmp.path(), 3, Some("sdk-py"));
        assert!(!is_monitorable_entrypoint_under(tmp.path(), 3));
    }

    #[test]
    fn entrypoint_filter_keeps_when_meta_missing() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(is_monitorable_entrypoint_under(tmp.path(), 999));
    }

    #[test]
    fn entrypoint_filter_keeps_when_field_missing() {
        let tmp = tempfile::tempdir().unwrap();
        write_session_meta(tmp.path(), 4, None);
        assert!(is_monitorable_entrypoint_under(tmp.path(), 4));
    }

    #[test]
    fn entrypoint_filter_keeps_when_meta_malformed() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(".claude").join("sessions");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("5.json"), "not json").unwrap();
        assert!(is_monitorable_entrypoint_under(tmp.path(), 5));
    }

    #[test]
    fn path_cache_evicts_stale_entry_when_jsonl_gone() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let cwd = PathBuf::from("/Users/test/proj");
        let session_id = "stale";
        let stale_dir = home.join(".claude").join("projects").join("old-location");
        std::fs::create_dir_all(&stale_dir).unwrap();
        let mut cache: HashMap<String, PathBuf> = HashMap::new();
        cache.insert(session_id.to_string(), stale_dir.clone());

        let _result = lookup_with_cache(home, &mut cache, &cwd, session_id);
        assert!(!cache.contains_key(session_id));
    }

    #[test]
    fn metadata_sessions_keep_live_vscode_session_with_jsonl() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let pid = 42;
        let cwd = PathBuf::from("/Users/test/proj");
        let session_id = "vscode-session";

        let sessions_dir = home.join(".claude").join("sessions");
        std::fs::create_dir_all(&sessions_dir).unwrap();
        std::fs::write(
            sessions_dir.join(format!("{pid}.json")),
            format!(
                r#"{{
                    "pid":{pid},
                    "sessionId":"{session_id}",
                    "cwd":"{}",
                    "entrypoint":"claude-vscode",
                    "kind":"interactive",
                    "startedAt":1700000000000,
                    "name":"proj-vscode",
                    "status":null
                }}"#,
                cwd.display()
            ),
        )
        .unwrap();

        let encoded = encode_path_for_matching(&cwd.to_string_lossy());
        let project_dir = home.join(".claude").join("projects").join(encoded);
        std::fs::create_dir_all(&project_dir).unwrap();
        std::fs::write(project_dir.join(format!("{session_id}.jsonl")), b"{}\n").unwrap();

        let mut cache = HashMap::new();
        let sessions = metadata_sessions_under(home, &mut cache, &HashSet::new(), |p| p == pid);

        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].pid, pid);
        assert_eq!(sessions[0].session_id.as_deref(), Some(session_id));
        assert_eq!(sessions[0].official_name.as_deref(), Some("proj-vscode"));
        assert_eq!(sessions[0].project_path, project_dir);
    }

    #[test]
    fn metadata_sessions_skip_dead_pids() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        write_session_meta(home, 99, Some("claude-vscode"));
        let mut cache = HashMap::new();
        let sessions = metadata_sessions_under(home, &mut cache, &HashSet::new(), |_| false);
        assert!(sessions.is_empty());
    }
}
