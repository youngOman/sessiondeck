use crate::session::source::{CliActivity, DetectedSession, DetectionDiagnostics, SessionSource};
use crate::session::{
    determine_status, get_pending_tool_input, get_pending_tool_name,
    last_conversation_entry_recent, parse_last_n_entries, parse_sessions_index, SessionStatus,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

/// Combined session information
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub id: String,
    pub pid: u32,
    pub session_name: String,
    pub custom_title: Option<String>,
    pub project_path: String,
    pub git_branch: Option<String>,
    pub first_prompt: String,
    pub summary: Option<String>,
    pub message_count: u32,
    pub modified: String,
    pub status: SessionStatus,
    pub latest_message: String,
    pub pending_tool_name: Option<String>,
    /// The input/arguments of the pending tool (when status is NeedsPermission)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_tool_input: Option<serde_json::Value>,
    /// Session ID of the PM that spawned this session (if it's a c9watch worker).
    /// Populated in polling.rs by overlay from `~/.claude/c9watch/workers/*/meta.json`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_of: Option<String>,
    /// User-set name from `claude agents` (Ctrl+T background-pinned sessions).
    /// Only populated by the CLI backend; legacy backend leaves this None.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub official_name: Option<String>,
    /// Session start time in ms since epoch (from `claude agents --json`).
    /// Only populated by the CLI backend; legacy backend leaves this None.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at_ms: Option<i64>,
}

/// Cache for native custom titles, keyed by file path.
/// Stores (mtime_as_nanos, cached_title) to avoid re-scanning JSONL files every poll cycle.
static NATIVE_TITLE_CACHE: LazyLock<Mutex<HashMap<std::path::PathBuf, (u64, Option<String>)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// How long a resolved git branch stays cached before we re-run `git`.
/// Keeps us from spawning a git subprocess for every session on every 2s poll,
/// while still reflecting a branch switch within a few seconds.
const GIT_BRANCH_TTL: Duration = Duration::from_secs(5);

/// Cache of cwd → (resolved branch, when it was resolved), keyed by working dir.
static GIT_BRANCH_CACHE: LazyLock<Mutex<HashMap<PathBuf, (Option<String>, Instant)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Resolves the *current* git branch for a session's working directory by asking
/// git directly, cached with a short TTL. Returns `None` when the directory is
/// not a git repo, git isn't available, or HEAD is detached — callers treat that
/// as "no branch to show".
pub(crate) fn get_cached_git_branch(cwd: &Path) -> Option<String> {
    if let Ok(mut cache) = GIT_BRANCH_CACHE.lock() {
        if let Some((branch, resolved_at)) = cache.get(cwd) {
            if resolved_at.elapsed() < GIT_BRANCH_TTL {
                return branch.clone();
            }
        }
        let branch = resolve_git_branch(cwd);
        cache.insert(cwd.to_path_buf(), (branch.clone(), Instant::now()));
        branch
    } else {
        // Mutex poisoned — fall back to a direct query.
        resolve_git_branch(cwd)
    }
}

/// Runs `git rev-parse --abbrev-ref HEAD` in `cwd` and returns the branch name.
/// Returns `None` for non-repos, errors, detached HEAD, or empty output.
fn resolve_git_branch(cwd: &Path) -> Option<String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let branch = String::from_utf8_lossy(&output.stdout).trim().to_string();
    // "HEAD" means detached — not a useful branch label.
    if branch.is_empty() || branch == "HEAD" {
        None
    } else {
        Some(branch)
    }
}

/// Look up the native custom title for a session JSONL, using a mtime-based cache.
pub(crate) fn get_cached_native_title(path: &Path) -> Option<String> {
    let mtime = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    if let Ok(mut cache) = NATIVE_TITLE_CACHE.lock() {
        if let Some((cached_mtime, cached_title)) = cache.get(path) {
            if *cached_mtime == mtime {
                return cached_title.clone();
            }
        }
        // Cache miss or stale — re-scan
        let title = crate::session::parser::get_native_custom_title_from_file(path);
        cache.insert(path.to_path_buf(), (mtime, title.clone()));
        title
    } else {
        // Mutex poisoned — fallback to direct read
        crate::session::parser::get_native_custom_title_from_file(path)
    }
}

/// Combines the existing heuristic-based SessionStatus with the CLI activity signal.
///
/// CLI activity NEVER overrides NeedsAttention or Connecting — those stay driven by
/// JSONL content + PermissionChecker. It only refines Working vs WaitingForInput.
pub fn merge_cli_activity(
    heuristic: SessionStatus,
    cli: Option<CliActivity>,
    has_pending_tool: bool,
) -> SessionStatus {
    match (heuristic, cli) {
        (SessionStatus::NeedsAttention, _) => SessionStatus::NeedsAttention,
        (SessionStatus::Connecting, _) => SessionStatus::Connecting,
        (heuristic, None) => heuristic,
        (SessionStatus::WaitingForInput, Some(CliActivity::Busy)) => SessionStatus::Working,
        (SessionStatus::Working, Some(CliActivity::Idle)) if !has_pending_tool => {
            SessionStatus::WaitingForInput
        }
        (heuristic, _) => heuristic,
    }
}

/// Detect sessions and enrich them with status and conversation data.
/// Uses the shared detector state so direct CLI/WS lookups behave like polling
/// and Tauri commands, including Auto-mode legacy supplementation.
pub fn detect_and_enrich_sessions() -> Result<(Vec<Session>, DetectionDiagnostics), String> {
    let mut detector = crate::session::DetectorState::new();
    let (detected, diag) = detector
        .detect()
        .map_err(|e| format!("Failed to detect sessions: {}", e))?;
    enrich_detected_sessions(detected, diag)
}

/// Detect sessions using a SessionSource trait object and enrich them.
pub fn detect_and_enrich_sessions_with_source(
    source: &mut dyn SessionSource,
) -> Result<(Vec<Session>, DetectionDiagnostics), String> {
    let (detected, diag) = source
        .detect()
        .map_err(|e| format!("Failed to detect sessions: {}", e))?;
    enrich_detected_sessions(detected, diag)
}

/// Enrichment-only: takes already-detected sessions and adds JSONL-derived fields.
/// Split out so callers can drop a lock before doing slow JSONL parsing.
pub fn enrich_detected_sessions(
    detected_sessions: Vec<DetectedSession>,
    diagnostics: DetectionDiagnostics,
) -> Result<(Vec<Session>, DetectionDiagnostics), String> {
    let custom_names = crate::session::CustomNames::load();
    let custom_titles = crate::session::CustomTitles::load();
    let mut sessions = Vec::new();
    let mut seen_ids: HashSet<String> = HashSet::new();

    for detected in detected_sessions {
        // Get session ID - if not found, skip this session
        let session_id = match &detected.session_id {
            Some(id) => id.clone(),
            None => {
                continue;
            }
        };

        // Skip duplicate session IDs (same session can appear in multiple project dirs)
        if seen_ids.contains(&session_id) {
            continue;
        }
        seen_ids.insert(session_id.clone());

        // Try to parse sessions-index.json to get basic info (optional)
        let index_path = detected.project_path.join("sessions-index.json");
        let sessions_index = parse_sessions_index(&index_path).ok();

        // Find the matching entry in the index (if index exists)
        let session_entry = sessions_index.as_ref().and_then(|index| {
            index
                .entries
                .iter()
                .find(|entry| entry.session_id == session_id)
        });

        let (first_prompt, summary, message_count, modified, git_branch) = match session_entry {
            Some(entry) => {
                // Guard: if sessions-index first_prompt is a system command, try JSONL fallback
                let fp = if crate::session::parser::is_system_content(&entry.first_prompt) {
                    let session_file_path =
                        detected.project_path.join(format!("{}.jsonl", session_id));
                    get_first_prompt_from_jsonl(&session_file_path)
                        .unwrap_or_else(|| entry.first_prompt.clone())
                } else {
                    entry.first_prompt.clone()
                };
                (
                    fp,
                    entry.summary.clone(),
                    entry.message_count,
                    entry.modified.clone(),
                    Some(entry.git_branch.clone()),
                )
            }
            None => {
                // Session not in index or index doesn't exist - use fallback values
                let session_file_path = detected.project_path.join(format!("{}.jsonl", session_id));

                // Try to get first prompt from JSONL file
                let first_prompt =
                    get_first_prompt_from_jsonl(&session_file_path).unwrap_or_else(|| {
                        if detected.started_at_ms.is_some() {
                            "(No conversation yet)".to_string()
                        } else {
                            "(Active session)".to_string()
                        }
                    });

                // Count messages in the file
                let message_count = count_messages_in_jsonl(&session_file_path);

                // Get file modification time. Fall back to started_at_ms for
                // CLI-sourced placeholder sessions (no JSONL yet) so the frontend
                // doesn't choke on `new Date("").getTime()` → NaN when sorting.
                let modified = std::fs::metadata(&session_file_path)
                    .and_then(|m| m.modified())
                    .ok()
                    .map(|t| {
                        let datetime: DateTime<Utc> = t.into();
                        datetime.to_rfc3339()
                    })
                    .or_else(|| {
                        detected.started_at_ms.and_then(|ms| {
                            DateTime::<Utc>::from_timestamp_millis(ms).map(|dt| dt.to_rfc3339())
                        })
                    })
                    .unwrap_or_default();

                (first_prompt, None, message_count, modified, None)
            }
        };

        // Parse the session JSONL file to determine status and get latest message.
        //
        // We read a generous tail (200 lines, not 20): newer Claude Code versions
        // append large bursts of metadata entries (last-prompt, mode,
        // permission-mode, ai-title, queue-operation, …) after a turn ends. If the
        // window is too small it can contain ONLY metadata and zero User/Assistant
        // entries, which makes determine_status fall through to Connecting — leaving
        // a long-finished session wrongly grouped under "Working". 200 lines
        // comfortably reaches the real conversation while still only reading the
        // file's tail.
        let session_file_path = detected.project_path.join(format!("{}.jsonl", session_id));
        let entries = match parse_last_n_entries(&session_file_path, 200) {
            Ok(entries) => entries,
            Err(e) => {
                crate::debug_log::log_warn(&format!(
                    "Failed to parse session file for {}: {}",
                    session_id, e
                ));
                vec![]
            }
        };

        let pending_tool_name = get_pending_tool_name(&entries);

        let heuristic_status = if entries.is_empty() {
            SessionStatus::Connecting
        } else {
            let raw_status = determine_status(&entries);
            // Override WaitingForInput to Working when the session is genuinely
            // streaming: the JSONL file was just touched AND the last real
            // conversation entry is itself recent. The recency gate is essential —
            // newer Claude Code versions keep appending metadata entries
            // (last-prompt, mode, ai-title, …) long after a session ends, which
            // keeps the file mtime fresh; without the gate those writes would pin a
            // finished session on "Working" forever.
            if raw_status == SessionStatus::WaitingForInput
                && is_file_recently_modified(&session_file_path, 8)
                && last_conversation_entry_recent(&entries, 30)
            {
                SessionStatus::Working
            } else {
                raw_status
            }
        };
        let status = merge_cli_activity(
            heuristic_status,
            detected.cli_activity,
            pending_tool_name.is_some(),
        );

        let latest_message = get_latest_message_from_entries(&entries);
        let pending_tool_input = get_pending_tool_input(&entries);

        // Skip empty sessions (0 messages) UNLESS CLI-sourced — `claude agents --json`
        // confirms the agent is live even when no project JSONL exists (SDK-based
        // interactive sessions never write to ~/.claude/projects/). Render a
        // placeholder card so the dashboard count matches `claude agents --json`.
        let cli_sourced = detected.started_at_ms.is_some();
        if message_count == 0 && !cli_sourced {
            continue;
        }

        // Use custom name if available, otherwise use detected project name
        let session_name = custom_names
            .get(&session_id)
            .cloned()
            .unwrap_or(detected.project_name);

        // Get custom title: Claude Code native /rename takes priority over c9watch's own.
        // Uses a static cache keyed by (path, mtime) to avoid re-scanning the JSONL every cycle.
        let native_title = get_cached_native_title(&session_file_path);
        let custom_title = native_title.or_else(|| custom_titles.get(&session_id).cloned());

        // Resolve the CURRENT git branch live from the working directory (cached
        // with a short TTL), so it reflects branch switches and works even when the
        // session isn't in sessions-index.json. Fall back to the index's static
        // value only when a live lookup yields nothing.
        let git_branch = get_cached_git_branch(&detected.cwd).or(git_branch);

        sessions.push(Session {
            id: session_id,
            pid: detected.pid,
            session_name,
            custom_title,
            project_path: detected.cwd.to_string_lossy().to_string(),
            git_branch,
            first_prompt,
            summary,
            message_count,
            modified,
            status,
            latest_message,
            pending_tool_name,
            pending_tool_input,
            worker_of: None,
            official_name: detected.official_name.clone(),
            started_at_ms: detected.started_at_ms,
        });
    }

    Ok((sessions, diagnostics))
}

/// Checks if a file was modified within the last N seconds
pub fn is_file_recently_modified(path: &Path, seconds: u64) -> bool {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .map(|modified| {
            modified
                .elapsed()
                .map(|elapsed| elapsed.as_secs() < seconds)
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// Extract the first user prompt from a session JSONL file (truncated to 100 chars).
pub fn get_first_prompt_from_jsonl(path: &Path) -> Option<String> {
    get_first_prompt_from_jsonl_raw(path).map(|s| truncate_string(&s, 100))
}

/// Extract the first user prompt from a session JSONL file (full text, no truncation).
pub fn get_first_prompt_from_jsonl_raw(path: &Path) -> Option<String> {
    let file = File::open(path).ok()?;
    let reader = BufReader::new(file);

    for line in reader.lines().map_while(Result::ok).take(50) {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) {
            if value.get("type").and_then(|t| t.as_str()) == Some("user") {
                if let Some(message) = value.get("message") {
                    if let Some(content) = message.get("content") {
                        if let Some(text) = content.as_str() {
                            // Skip system-generated local command messages
                            if crate::session::parser::is_system_content(text) {
                                continue;
                            }
                            return Some(text.to_string());
                        } else if let Some(arr) = content.as_array() {
                            for item in arr {
                                if item.get("type").and_then(|t| t.as_str()) == Some("text") {
                                    if let Some(text) = item.get("text").and_then(|t| t.as_str()) {
                                        return Some(text.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

/// Truncate a string to a maximum length (character-safe for UTF-8)
pub fn truncate_string(s: &str, max_chars: usize) -> String {
    let char_count = s.chars().count();
    if char_count <= max_chars {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max_chars).collect();
        format!("{}...", truncated)
    }
}

/// Extract the latest message content from session entries
pub fn get_latest_message_from_entries(entries: &[crate::session::parser::SessionEntry]) -> String {
    if entries.is_empty() {
        return String::new();
    }

    for entry in entries.iter().rev() {
        match entry {
            crate::session::parser::SessionEntry::User { message, .. } => {
                // Skip tool result entries and system-generated command messages
                if message.is_tool_result
                    || crate::session::parser::is_system_content(&message.content)
                {
                    continue;
                }
                return truncate_string(&message.content, 200);
            }
            crate::session::parser::SessionEntry::Assistant { message, .. } => {
                for content in message.content.iter().rev() {
                    match content {
                        crate::session::parser::MessageContent::Text { text } => {
                            return truncate_string(text, 200);
                        }
                        crate::session::parser::MessageContent::Thinking { thinking, .. } => {
                            return truncate_string(thinking, 200);
                        }
                        crate::session::parser::MessageContent::ToolUse { name, .. } => {
                            return format!("Executing {}...", name);
                        }
                        _ => continue,
                    }
                }
            }
            _ => continue,
        }
    }

    String::new()
}

/// Count user/assistant messages in a JSONL file.
/// Skips system-injected user messages (local commands, slash commands, etc.)
pub fn count_messages_in_jsonl(path: &Path) -> u32 {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return 0,
    };
    let reader = BufReader::new(file);
    let mut count = 0u32;

    for line in reader.lines().map_while(Result::ok) {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) {
            if let Some(msg_type) = value.get("type").and_then(|t| t.as_str()) {
                match msg_type {
                    "assistant" => count += 1,
                    "user" => {
                        // Skip system-injected user messages
                        if let Some(content) = value
                            .get("message")
                            .and_then(|m| m.get("content"))
                            .and_then(|c| c.as_str())
                        {
                            if !crate::session::parser::is_system_content(content) {
                                count += 1;
                            }
                        } else {
                            // Array content (tool results) — still count them
                            count += 1;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_git_branch_resolves_for_this_repo() {
        // The crate itself lives inside a git repo, so resolving the branch for
        // the manifest dir must yield a non-empty branch name.
        let repo_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let branch = get_cached_git_branch(repo_dir);
        assert!(
            branch.as_deref().is_some_and(|b| !b.is_empty()),
            "expected a branch name for the crate's own repo, got {branch:?}"
        );
    }

    #[test]
    fn test_git_branch_none_for_non_repo() {
        // A directory that is not a git repo must resolve to None, not an error.
        let tmp = std::env::temp_dir();
        assert_eq!(get_cached_git_branch(&tmp), None);
    }

    #[test]
    fn test_git_branch_none_for_missing_dir() {
        let missing = Path::new("/tmp/c9watch-definitely-not-here-xyz-123");
        assert_eq!(get_cached_git_branch(missing), None);
    }

    #[test]
    fn test_truncate_string_no_truncation() {
        assert_eq!(truncate_string("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_string_exact_boundary() {
        assert_eq!(truncate_string("hello", 5), "hello");
    }

    #[test]
    fn test_truncate_string_over_boundary() {
        assert_eq!(truncate_string("hello world", 5), "hello...");
    }

    #[test]
    fn test_truncate_string_empty() {
        assert_eq!(truncate_string("", 10), "");
    }

    #[test]
    fn test_truncate_string_zero_max() {
        assert_eq!(truncate_string("hello", 0), "...");
        assert!(!truncate_string("hello", 0).contains('h'));
    }

    #[test]
    fn test_truncate_string_single_char_limit() {
        assert_eq!(truncate_string("hello", 1), "h...");
    }

    #[test]
    fn test_truncate_string_utf8_accented() {
        assert_eq!(truncate_string("héllo", 3), "hél...");
    }

    #[test]
    fn test_truncate_string_utf8_cjk() {
        assert_eq!(truncate_string("你好世界", 2), "你好...");
    }

    #[test]
    fn test_truncate_string_utf8_emoji() {
        assert_eq!(truncate_string("Hello 👋 World", 7), "Hello 👋...");
    }
}

#[cfg(test)]
mod merge_tests {
    use super::*;
    use crate::session::source::CliActivity;
    use crate::session::SessionStatus;

    #[test]
    fn merge_preserves_needs_attention_when_busy() {
        let merged = merge_cli_activity(
            SessionStatus::NeedsAttention,
            Some(CliActivity::Busy),
            false,
        );
        assert_eq!(merged, SessionStatus::NeedsAttention);
    }

    #[test]
    fn merge_preserves_needs_attention_when_idle() {
        let merged = merge_cli_activity(
            SessionStatus::NeedsAttention,
            Some(CliActivity::Idle),
            false,
        );
        assert_eq!(merged, SessionStatus::NeedsAttention);
    }

    #[test]
    fn merge_preserves_connecting() {
        let merged = merge_cli_activity(SessionStatus::Connecting, Some(CliActivity::Busy), false);
        assert_eq!(merged, SessionStatus::Connecting);
    }

    #[test]
    fn merge_busy_promotes_waiting_to_working() {
        let merged = merge_cli_activity(
            SessionStatus::WaitingForInput,
            Some(CliActivity::Busy),
            false,
        );
        assert_eq!(merged, SessionStatus::Working);
    }

    #[test]
    fn merge_idle_downgrades_working_without_pending_tool() {
        let merged = merge_cli_activity(SessionStatus::Working, Some(CliActivity::Idle), false);
        assert_eq!(merged, SessionStatus::WaitingForInput);
    }

    #[test]
    fn merge_idle_keeps_working_when_pending_tool() {
        let merged = merge_cli_activity(SessionStatus::Working, Some(CliActivity::Idle), true);
        assert_eq!(merged, SessionStatus::Working);
    }

    #[test]
    fn merge_none_returns_heuristic_unchanged() {
        let merged = merge_cli_activity(SessionStatus::Working, None, false);
        assert_eq!(merged, SessionStatus::Working);
        let merged = merge_cli_activity(SessionStatus::WaitingForInput, None, true);
        assert_eq!(merged, SessionStatus::WaitingForInput);
    }
}

#[cfg(test)]
mod placeholder_tests {
    use super::*;
    use crate::session::source::{DetectedSession, DetectionDiagnostics, SessionKind};
    use std::path::PathBuf;

    #[test]
    fn cli_placeholder_session_has_valid_modified_from_started_at_ms() {
        // CLI-sourced session with no JSONL → must still produce parseable RFC3339
        // `modified` so `new Date(modified).getTime()` doesn't yield NaN on the
        // frontend (which would scramble sort/group ordering).
        let tmp = tempfile::tempdir().unwrap();
        let detected = DetectedSession {
            pid: 12345,
            cwd: PathBuf::from("/tmp/nonexistent"),
            project_path: tmp.path().join("never-existed"),
            session_id: Some("11111111-2222-3333-4444-555555555555".to_string()),
            project_name: "nonexistent".to_string(),
            kind: SessionKind::Interactive,
            started_at_ms: Some(1_700_000_000_000),
            official_name: None,
            cli_activity: None,
        };
        let (sessions, _) =
            enrich_detected_sessions(vec![detected], DetectionDiagnostics::default()).unwrap();
        assert_eq!(sessions.len(), 1, "CLI placeholder should be emitted");
        let s = &sessions[0];
        assert!(!s.modified.is_empty(), "modified must not be empty");
        let parsed = DateTime::parse_from_rfc3339(&s.modified);
        assert!(
            parsed.is_ok(),
            "modified must parse as RFC3339, got: {}",
            s.modified
        );
        assert_eq!(s.started_at_ms, Some(1_700_000_000_000));
    }

    #[test]
    fn legacy_session_without_jsonl_still_skipped() {
        // Legacy backend leaves started_at_ms = None. Without JSONL, no message
        // count, no real data — keep dropping these to avoid the legacy ghost-pid bug.
        let tmp = tempfile::tempdir().unwrap();
        let detected = DetectedSession::with_legacy_defaults(
            42,
            PathBuf::from("/tmp/legacy"),
            tmp.path().join("legacy-empty"),
            Some("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_string()),
            "legacy".to_string(),
        );
        let (sessions, _) =
            enrich_detected_sessions(vec![detected], DetectionDiagnostics::default()).unwrap();
        assert!(
            sessions.is_empty(),
            "legacy empty-JSONL session must be skipped"
        );
    }
}
