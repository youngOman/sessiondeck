use serde::Deserialize;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System, UpdateKind};

use super::source::{DetectedSession, DetectionDiagnostics, SessionDetectorError, SessionSource};

/// Session detector that finds running Claude processes and matches them to session files
pub struct LegacySessionSource {
    system: System,
    claude_projects_dir: PathBuf,
    claude_sessions_dir: PathBuf,
}

impl LegacySessionSource {
    /// Creates a new LegacySessionSource
    pub fn new() -> Result<Self, SessionDetectorError> {
        let home_dir = dirs::home_dir().ok_or(SessionDetectorError::HomeDirectoryNotFound)?;

        let claude_projects_dir = home_dir.join(".claude").join("projects");
        let claude_sessions_dir = home_dir.join(".claude").join("sessions");

        Ok(Self {
            system: System::new_with_specifics(
                RefreshKind::new().with_processes(
                    ProcessRefreshKind::new()
                        .with_exe(UpdateKind::OnlyIfNotSet)
                        .with_cmd(UpdateKind::OnlyIfNotSet)
                        .with_cwd(UpdateKind::OnlyIfNotSet),
                ),
            ),
            claude_projects_dir,
            claude_sessions_dir,
        })
    }

    /// Detects all active Claude Code sessions
    pub fn detect_sessions(
        &mut self,
    ) -> Result<(Vec<DetectedSession>, DetectionDiagnostics), SessionDetectorError> {
        // Refresh process information (only what we need: name, cwd, start_time)
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::new()
                .with_exe(UpdateKind::OnlyIfNotSet)
                .with_cmd(UpdateKind::OnlyIfNotSet)
                .with_cwd(UpdateKind::OnlyIfNotSet),
        );

        // Find all running Claude processes
        let claude_processes = self.find_claude_processes();

        let total = claude_processes.len() as u32;
        let with_cwd = claude_processes.iter().filter(|p| p.cwd.is_some()).count() as u32;
        let diagnostics = DetectionDiagnostics {
            claude_processes_found: total,
            processes_with_cwd: with_cwd,
            fda_likely_needed: total > 0 && with_cwd == 0,
        };

        // If no Claude processes are running, return empty
        if claude_processes.is_empty() {
            return Ok((Vec::new(), diagnostics));
        }

        // Get all session project directories
        let project_dirs = self.enumerate_project_directories()?;

        // Find recently active sessions (modified in last 30 minutes)
        // and associate them with running processes
        let sessions = self.find_active_sessions(&claude_processes, &project_dirs);

        Ok((sessions, diagnostics))
    }

    /// Find sessions that are likely active based on running process count
    fn find_active_sessions(
        &self,
        processes: &[ClaudeProcess],
        project_dirs: &[PathBuf],
    ) -> Vec<DetectedSession> {
        // Collect all session files with their modification times and project path
        // Tuple: (modified_time, jsonl_path, project_dir, project_path, project_name,
        // has_reliable_path, recorded_cwd)
        let mut session_files: Vec<(
            std::time::SystemTime,
            PathBuf,
            PathBuf,
            PathBuf,
            String,
            bool,
            Option<PathBuf>,
        )> = Vec::new();

        for project_dir in project_dirs {
            if let Ok(entries) = fs::read_dir(project_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();

                    // Check if it's a JSONL file (UUID format, not subagent files)
                    if path.is_file() && path.extension().is_some_and(|ext| ext == "jsonl") {
                        // Skip files that don't look like UUIDs (e.g., agent-*.jsonl)
                        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                            if stem.starts_with("agent-") {
                                continue;
                            }
                        }

                        if let Ok(metadata) = fs::metadata(&path) {
                            if let Ok(modified) = metadata.modified() {
                                // Get session ID and project info
                                if let Some(session_id) = path
                                    .file_stem()
                                    .and_then(|s| s.to_str())
                                    .map(|s| s.to_string())
                                {
                                    // Try to get project info from sessions-index.json
                                    // This is the ONLY reliable source of project path
                                    let (project_path, project_name, has_reliable_path) = match self
                                        .get_project_info_from_index(project_dir, &session_id)
                                    {
                                        Some((path, name)) => (path, name, true),
                                        None => {
                                            // No reliable path available - use directory name as display only
                                            // Don't try to decode it (decoding is ambiguous due to dashes)
                                            let dir_name = project_dir
                                                .file_name()
                                                .and_then(|n| n.to_str())
                                                .unwrap_or("unknown");

                                            // Just use the last segment after splitting on dash as a rough name
                                            // This is for display only, not for matching
                                            let name = dir_name
                                                .rsplit('-')
                                                .next()
                                                .unwrap_or("unknown")
                                                .to_string();

                                            // Use the project_dir as a placeholder (will use fallback PID assignment)
                                            (project_dir.clone(), name, false)
                                        }
                                    };

                                    session_files.push((
                                        modified,
                                        path.clone(),
                                        project_dir.clone(),
                                        project_path,
                                        project_name,
                                        has_reliable_path,
                                        latest_recorded_cwd(&path),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }

        // Sort by modification time (most recent first)
        session_files.sort_by(|a, b| b.0.cmp(&a.0));

        // Process-centric approach: for each process, find its matching session
        // This ensures we only show sessions that have actual running processes
        let mut sessions = Vec::new();
        let mut used_session_ids: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        // Sort processes by start_time (newest first) to match newest processes first
        let mut sorted_processes: Vec<&ClaudeProcess> = processes.iter().collect();
        sorted_processes.sort_by(|a, b| b.start_time.cmp(&a.start_time));

        for proc in sorted_processes {
            let proc_cwd = match &proc.cwd {
                Some(cwd) => cwd,
                None => continue, // Skip processes without cwd
            };

            // Primary: try to resolve session ID from ~/.claude/sessions/<pid>.json
            // This file is the authoritative source and is updated after /clear,
            // so we always get the correct current session.
            if let Some(meta) = self.read_session_metadata(proc.pid) {
                if !used_session_ids.contains(&meta.session_id) {
                    // Find the matching session file and project info
                    if let Some((_, _, project_dir, _, project_name, _, _)) =
                        session_files.iter().find(|(_, path, _, _, _, _, _)| {
                            path.file_stem().and_then(|s| s.to_str()) == Some(&meta.session_id)
                        })
                    {
                        used_session_ids.insert(meta.session_id.clone());
                        sessions.push(DetectedSession::with_legacy_defaults(
                            proc.pid,
                            proc_cwd.clone(),
                            project_dir.clone(),
                            Some(meta.session_id),
                            project_name.clone(),
                        ));
                        continue;
                    }
                }
            }

            // Fallback: heuristic matching by encoded CWD + modification time.
            // Used when pid.json doesn't exist (e.g., older Claude Code versions).
            let cwd_str = proc_cwd.to_string_lossy();
            let encoded_cwd = encode_path_for_matching(&cwd_str);

            // Helper closure to check if a session matches the process path
            let path_matches = |project_dir: &Path,
                                project_path: &Path,
                                has_reliable_path: bool,
                                recorded_cwd: Option<&PathBuf>|
             -> bool {
                if let Some(recorded_cwd) = recorded_cwd {
                    return proc_cwd == recorded_cwd;
                }

                let dir_name = project_dir
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");

                // Method 1: Direct path comparison (exact or subdirectory match)
                let direct_match = if has_reliable_path {
                    proc_cwd == project_path || proc_cwd.starts_with(project_path)
                } else {
                    false
                };

                // Method 2: Encoded path comparison
                let encoded_match = dir_name == encoded_cwd;

                direct_match || encoded_match
            };

            // Helper closure to check if session is not already used
            let session_available = |path: &Path| -> bool {
                match path.file_stem().and_then(|s| s.to_str()) {
                    Some(id) => !used_session_ids.contains(id),
                    None => false,
                }
            };

            // Find session with activity after process start
            // Only match sessions that were modified AFTER the process started
            // This prevents matching a new Claude instance (with no session file yet)
            // to an older session from the same project directory
            let matching_session = session_files.iter().find(
                |(
                    modified,
                    path,
                    project_dir,
                    project_path,
                    _,
                    has_reliable_path,
                    recorded_cwd,
                )| {
                    if !session_available(path) {
                        return false;
                    }

                    // Check if the session was modified after the process started
                    let session_active_after_proc_start =
                        match modified.duration_since(std::time::UNIX_EPOCH) {
                            Ok(duration) => {
                                let session_modified_secs = duration.as_secs();
                                // Session must have been modified at or after process start (with 5s buffer)
                                session_modified_secs + 5 >= proc.start_time
                            }
                            Err(_) => false,
                        };

                    session_active_after_proc_start
                        && path_matches(
                            project_dir,
                            project_path,
                            *has_reliable_path,
                            recorded_cwd.as_ref(),
                        )
                },
            );

            if let Some((_, path, project_dir, _, project_name, _, _)) = matching_session {
                if let Some(session_id) = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .map(|s| s.to_string())
                {
                    used_session_ids.insert(session_id.clone());

                    sessions.push(DetectedSession::with_legacy_defaults(
                        proc.pid,
                        proc_cwd.clone(),
                        project_dir.clone(),
                        Some(session_id),
                        project_name.clone(),
                    ));
                }
            } else {
                crate::debug_log::log_warn(&format!(
                    "PID={}: no matching session found for cwd={}",
                    proc.pid,
                    proc_cwd.display()
                ));
            }
        }

        sessions
    }

    /// Reads session metadata from ~/.claude/sessions/<pid>.json if it exists.
    fn read_session_metadata(&self, pid: u32) -> Option<PidSessionMeta> {
        let meta_path = self.claude_sessions_dir.join(format!("{}.json", pid));
        let content = fs::read_to_string(&meta_path).ok()?;
        serde_json::from_str::<PidSessionMeta>(&content).ok()
    }

    /// Get project info from sessions-index.json for a given session ID
    fn get_project_info_from_index(
        &self,
        project_dir: &Path,
        session_id: &str,
    ) -> Option<(PathBuf, String)> {
        let index_path = project_dir.join("sessions-index.json");

        if let Ok(content) = fs::read_to_string(&index_path) {
            if let Ok(index) = serde_json::from_str::<SessionsIndex>(&content) {
                if let Some(entries) = &index.entries {
                    for entry in entries {
                        if entry.session_id == session_id {
                            if let Some(proj_path) = &entry.project_path {
                                let path = PathBuf::from(proj_path);
                                let name = path
                                    .file_name()
                                    .and_then(|n| n.to_str())
                                    .unwrap_or("unknown")
                                    .to_string();
                                return Some((path, name));
                            }
                        }
                    }

                    // If session not found in index, use first entry's project path as fallback
                    if let Some(first) = entries.first() {
                        if let Some(proj_path) = &first.project_path {
                            let path = PathBuf::from(proj_path);
                            let name = path
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("unknown")
                                .to_string();
                            return Some((path, name));
                        }
                    }
                }
            }
        }

        None
    }

    /// Finds all processes with name "claude" or whose command-line args contain "claude".
    /// On macOS, npm-installed Claude Code runs as "node" so we also check process.cmd().
    fn find_claude_processes(&self) -> Vec<ClaudeProcess> {
        let mut processes = Vec::new();

        for (pid, process) in self.system.processes() {
            let name = process.name().to_string_lossy();

            // Skip our own process
            if name.contains("c9watch") {
                continue;
            }

            // Check process name first (works for direct installs). Keep this
            // strict so Claude Desktop helpers and MCP servers with args like
            // `--agent claudeCodeCLI` don't steal Claude Code sessions.
            let name_match = name.eq_ignore_ascii_case("claude");
            if name_match && process.exe().is_some_and(is_claude_desktop_app) {
                continue;
            }

            // Also check command-line args (handles npm-installed Claude Code
            // where process.name() returns "node")
            let cmd_match = !name_match
                && process
                    .cmd()
                    .iter()
                    .any(|arg| is_claude_code_arg(&arg.to_string_lossy()));

            if name_match || cmd_match {
                let cwd = process.cwd().map(|p| p.to_path_buf());
                let start_time = process.start_time();

                processes.push(ClaudeProcess {
                    pid: pid.as_u32(),
                    cwd,
                    start_time,
                });
            }
        }

        let lsof_cwds = pid_cwds(
            &processes
                .iter()
                .map(|process| process.pid)
                .collect::<Vec<_>>(),
        );
        for process in &mut processes {
            if let Some(cwd) = lsof_cwds.get(&process.pid) {
                process.cwd = Some(cwd.clone());
            }
        }

        processes
    }

    /// Enumerates all project directories in ~/.claude/projects/
    fn enumerate_project_directories(&self) -> Result<Vec<PathBuf>, SessionDetectorError> {
        let mut project_dirs = Vec::new();

        // Check if the claude projects directory exists
        if !self.claude_projects_dir.exists() {
            return Ok(project_dirs);
        }

        // Read all entries in the projects directory
        let entries = fs::read_dir(&self.claude_projects_dir)?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            // Only include directories
            if path.is_dir() {
                project_dirs.push(path);
            }
        }

        Ok(project_dirs)
    }
}

fn pid_cwds(pids: &[u32]) -> HashMap<u32, PathBuf> {
    if pids.is_empty() {
        return HashMap::new();
    }

    let list = pids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let output = match Command::new("lsof")
        .args(["-a", "-d", "cwd", "-p", &list, "-Fpn"])
        .output()
    {
        Ok(output) if !output.stdout.is_empty() => output,
        _ => return HashMap::new(),
    };

    parse_lsof_cwds(&String::from_utf8_lossy(&output.stdout))
}

fn latest_recorded_cwd(path: &Path) -> Option<PathBuf> {
    const TAIL_BYTES: u64 = 64 * 1024;

    let mut file = File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    let start = len.saturating_sub(TAIL_BYTES);
    file.seek(SeekFrom::Start(start)).ok()?;

    let mut raw = String::new();
    file.read_to_string(&mut raw).ok()?;
    if start > 0 {
        if let Some((_, rest)) = raw.split_once('\n') {
            raw = rest.to_string();
        }
    }

    latest_recorded_cwd_from_str(&raw)
}

fn is_claude_code_arg(arg: &str) -> bool {
    if arg.contains("c9watch") {
        return false;
    }

    if arg == "claude" {
        return true;
    }

    if Path::new(arg).file_name().and_then(|name| name.to_str()) == Some("claude") {
        return true;
    }

    // npm-installed Claude Code runs under node; the script path contains the
    // package name rather than ending in a `claude` binary.
    arg.contains("@anthropic-ai/claude-code") || arg.contains("/claude-code/")
}

fn is_claude_desktop_app(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str().to_string_lossy() == "Claude.app")
}

fn latest_recorded_cwd_from_str(raw: &str) -> Option<PathBuf> {
    let mut cwd = None;
    for line in raw.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if let Some(path) = value.get("cwd").and_then(|v| v.as_str()) {
            cwd = Some(PathBuf::from(path));
        }
    }
    cwd
}

fn parse_lsof_cwds(raw: &str) -> HashMap<u32, PathBuf> {
    let mut result = HashMap::new();
    let mut current_pid: Option<u32> = None;

    for line in raw.lines() {
        if let Some(pid) = line.strip_prefix('p') {
            current_pid = pid.parse::<u32>().ok();
        } else if let (Some(path), Some(pid)) = (line.strip_prefix('n'), current_pid) {
            result.insert(pid, PathBuf::from(path));
        }
    }

    result
}

impl Default for LegacySessionSource {
    fn default() -> Self {
        Self::new().expect("Failed to create LegacySessionSource")
    }
}

impl SessionSource for LegacySessionSource {
    fn detect(
        &mut self,
    ) -> Result<(Vec<DetectedSession>, DetectionDiagnostics), SessionDetectorError> {
        self.detect_sessions()
    }
    fn backend_name(&self) -> &'static str {
        "legacy"
    }
}

/// Encodes a path the same way Claude Code does for its project directory names:
/// every non-alphanumeric character is replaced with a dash.
pub(crate) fn encode_path_for_matching(path: &str) -> String {
    path.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

/// Internal representation of a Claude process
#[derive(Debug, Clone)]
struct ClaudeProcess {
    pid: u32,
    cwd: Option<PathBuf>,
    start_time: u64, // Process start time (seconds since epoch)
}

/// Session metadata from ~/.claude/sessions/<pid>.json
/// Written by Claude Code with the authoritative session ID for each process.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PidSessionMeta {
    session_id: String,
}

/// Structure of sessions-index.json
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionsIndex {
    #[allow(dead_code)]
    version: Option<u32>,
    entries: Option<Vec<SessionEntry>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionEntry {
    session_id: String,
    project_path: Option<String>,
    #[allow(dead_code)]
    full_path: Option<String>,
    #[allow(dead_code)]
    first_prompt: Option<String>,
    #[allow(dead_code)]
    summary: Option<String>,
    #[allow(dead_code)]
    message_count: Option<u32>,
    #[allow(dead_code)]
    git_branch: Option<String>,
    #[allow(dead_code)]
    modified: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_creation() {
        let result = LegacySessionSource::new();
        assert!(result.is_ok());
    }

    #[test]
    fn test_find_claude_processes() {
        let detector = LegacySessionSource::new().unwrap();
        let processes = detector.find_claude_processes();
        // This test will vary based on whether claude is running
        println!("Found {} claude processes", processes.len());
    }

    #[test]
    fn test_enumerate_project_directories() {
        let detector = LegacySessionSource::new().unwrap();
        let result = detector.enumerate_project_directories();
        assert!(result.is_ok());

        if let Ok(dirs) = result {
            println!("Found {} project directories", dirs.len());
        }
    }

    #[test]
    fn test_encode_path_for_matching() {
        // Must match Claude Code's encoding: replace every non-alphanumeric char with '-'.
        assert_eq!(
            encode_path_for_matching("/Users/Name/My_Project"),
            "-Users-Name-My-Project"
        );
        // Dots in paths (hidden dirs) become dashes
        assert_eq!(
            encode_path_for_matching("/Users/Name/.config/project"),
            "-Users-Name--config-project"
        );
        // Spaces become dashes
        assert_eq!(
            encode_path_for_matching("/Users/Name/My Project"),
            "-Users-Name-My-Project"
        );
        // Dots in project names
        assert_eq!(
            encode_path_for_matching("/Users/Name/project.v2"),
            "-Users-Name-project-v2"
        );
    }

    #[test]
    fn test_parse_lsof_cwds() {
        let parsed = parse_lsof_cwds(
            "p29906\nfcwd\nn/Users/young/Developer/pdf-demo\np5395\nfcwd\nn/Users/young\n",
        );

        assert_eq!(
            parsed.get(&29906),
            Some(&PathBuf::from("/Users/young/Developer/pdf-demo"))
        );
        assert_eq!(parsed.get(&5395), Some(&PathBuf::from("/Users/young")));
    }

    #[test]
    fn test_latest_recorded_cwd_from_str_uses_last_cwd() {
        let raw = r#"
{"type":"user","cwd":"/Users/young","sessionId":"a"}
{"type":"assistant","cwd":"/Users/young/Developer/pdf-demo","sessionId":"a"}
{"type":"last-prompt","sessionId":"a"}
"#;

        assert_eq!(
            latest_recorded_cwd_from_str(raw),
            Some(PathBuf::from("/Users/young/Developer/pdf-demo"))
        );
    }

    #[test]
    fn test_is_claude_code_arg() {
        assert!(is_claude_code_arg("claude"));
        assert!(is_claude_code_arg(
            "/Users/young/.vscode/extensions/anthropic.claude-code/resources/native-binary/claude"
        ));
        assert!(is_claude_code_arg(
            "/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/cli.js"
        ));
        assert!(!is_claude_code_arg("claudeCodeCLI"));
        assert!(!is_claude_code_arg("--agent"));
        assert!(!is_claude_code_arg("target/debug/c9watch"));
    }

    #[test]
    fn test_is_claude_desktop_app() {
        assert!(is_claude_desktop_app(Path::new(
            "/Applications/Claude.app/Contents/MacOS/Claude"
        )));
        assert!(!is_claude_desktop_app(Path::new(
            "/opt/homebrew/bin/claude"
        )));
    }
}
