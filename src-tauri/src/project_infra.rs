//! Project infrastructure scanner: which dev services are running for each
//! project directory, and on which host ports.
//!
//! Two sources, merged into one snapshot:
//! 1. Docker Compose containers — a single `docker ps` call, grouped by the
//!    `com.docker.compose.project` label. The `working_dir` label is the key
//!    used to match a compose project to a session's `project_path`.
//! 2. Bare dev servers (vite, uvicorn, go run, …) — `lsof` TCP listeners,
//!    kept only when the process cwd lives under $HOME so system daemons and
//!    GUI apps are excluded.

use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{LazyLock, Mutex};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PortMapping {
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceInfo {
    pub service: String,
    pub container_name: String,
    pub state: String,
    pub ports: Vec<PortMapping>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComposeProject {
    pub name: String,
    pub working_dir: String,
    pub config_files: Vec<String>,
    pub services: Vec<ServiceInfo>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BareServer {
    pub pid: u32,
    pub process: String,
    pub port: u16,
    pub cwd: String,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InfraSnapshot {
    pub compose_projects: Vec<ComposeProject>,
    pub standalone_containers: Vec<ServiceInfo>,
    pub bare_servers: Vec<BareServer>,
}

// ── Docker discovery ────────────────────────────────────────────────

/// GUI apps on macOS get a minimal PATH (/usr/bin:/bin:...), so `docker`
/// usually isn't resolvable — probe the common install locations too.
static DOCKER_PATH: LazyLock<Option<PathBuf>> = LazyLock::new(|| {
    let path_works = Command::new("docker")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if path_works {
        return Some(PathBuf::from("docker"));
    }

    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(home) = dirs::home_dir() {
        candidates.push(home.join(".orbstack/bin/docker"));
        candidates.push(home.join(".rd/bin/docker")); // Rancher Desktop
    }
    candidates.push(PathBuf::from("/usr/local/bin/docker"));
    candidates.push(PathBuf::from("/opt/homebrew/bin/docker"));
    candidates.push(PathBuf::from(
        "/Applications/Docker.app/Contents/Resources/bin/docker",
    ));
    candidates.into_iter().find(|p| p.exists())
});

// ── Compose / container scan ────────────────────────────────────────

/// One `docker ps` with label templates covers every compose project:
/// no per-project `docker compose ps` round-trips needed.
const DOCKER_PS_FORMAT: &str = "{{.Names}}\t{{.State}}\t{{.Ports}}\t{{.Label \"com.docker.compose.project\"}}\t{{.Label \"com.docker.compose.project.working_dir\"}}\t{{.Label \"com.docker.compose.service\"}}\t{{.Label \"com.docker.compose.project.config_files\"}}";

fn scan_docker() -> (Vec<ComposeProject>, Vec<ServiceInfo>) {
    let Some(docker) = DOCKER_PATH.as_ref() else {
        return (Vec::new(), Vec::new());
    };
    let output = match Command::new(docker)
        .args(["ps", "--format", DOCKER_PS_FORMAT])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return (Vec::new(), Vec::new()),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut projects: BTreeMap<String, ComposeProject> = BTreeMap::new();
    let mut standalone: Vec<ServiceInfo> = Vec::new();

    for line in stdout.lines() {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 7 {
            continue;
        }
        let (name, state, ports_str, project, working_dir, service, config_files) = (
            cols[0], cols[1], cols[2], cols[3], cols[4], cols[5], cols[6],
        );

        let svc = ServiceInfo {
            service: if service.is_empty() {
                name.to_string()
            } else {
                service.to_string()
            },
            container_name: name.to_string(),
            state: state.to_string(),
            ports: parse_ports(ports_str),
        };

        if project.is_empty() {
            standalone.push(svc);
        } else {
            projects
                .entry(project.to_string())
                .or_insert_with(|| ComposeProject {
                    name: project.to_string(),
                    working_dir: working_dir.to_string(),
                    config_files: config_files
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .collect(),
                    services: Vec::new(),
                })
                .services
                .push(svc);
        }
    }

    let mut projects: Vec<ComposeProject> = projects.into_values().collect();
    for p in &mut projects {
        p.services.sort_by(|a, b| a.service.cmp(&b.service));
    }
    standalone.sort_by(|a, b| a.container_name.cmp(&b.container_name));
    (projects, standalone)
}

/// Parse a `docker ps` Ports column, e.g.
/// `0.0.0.0:15432->5432/tcp, [::]:15432->5432/tcp, 6379/tcp`.
/// Unpublished ports (no `->`) are skipped; IPv4/IPv6 duplicates collapse.
fn parse_ports(s: &str) -> Vec<PortMapping> {
    let mut seen: HashSet<(u16, u16, String)> = HashSet::new();
    let mut result = Vec::new();
    for entry in s.split(',').map(str::trim) {
        let Some((lhs, rhs)) = entry.split_once("->") else {
            continue;
        };
        let host_port = lhs.rsplit(':').next().and_then(|p| p.parse::<u16>().ok());
        let (container_port, protocol) = match rhs.split_once('/') {
            Some((c, proto)) => (c.parse::<u16>().ok(), proto),
            None => (rhs.parse::<u16>().ok(), "tcp"),
        };
        if let (Some(hp), Some(cp)) = (host_port, container_port) {
            if seen.insert((hp, cp, protocol.to_string())) {
                result.push(PortMapping {
                    host_port: hp,
                    container_port: cp,
                    protocol: protocol.to_string(),
                });
            }
        }
    }
    result.sort_by_key(|p| p.host_port);
    result
}

// ── Bare dev server scan (lsof) ─────────────────────────────────────

fn scan_bare_servers() -> Vec<BareServer> {
    // -F field output: p<pid> / c<command> / n<name> lines, machine-parseable.
    let output = match Command::new("lsof")
        .args(["-nP", "-iTCP", "-sTCP:LISTEN", "-Fpcn"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    // lsof exits non-zero when some FDs are unreadable — its stdout is still valid.
    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut cur_pid: u32 = 0;
    let mut cur_cmd = String::new();
    let mut listeners: Vec<(u32, String, u16)> = Vec::new();
    let mut seen: HashSet<(u32, u16)> = HashSet::new();

    for line in stdout.lines() {
        match line.as_bytes().first() {
            Some(b'p') => cur_pid = line[1..].parse().unwrap_or(0),
            Some(b'c') => cur_cmd = line[1..].to_string(),
            Some(b'n') => {
                let port = line.rsplit(':').next().and_then(|p| p.parse::<u16>().ok());
                if let Some(port) = port {
                    if cur_pid != 0 && seen.insert((cur_pid, port)) {
                        listeners.push((cur_pid, cur_cmd.clone(), port));
                    }
                }
            }
            _ => {}
        }
    }

    // Docker's port proxies already show up in the compose scan.
    let is_dockerish = |c: &str| {
        let l = c.to_lowercase();
        l.contains("docker") || l.contains("orbstack") || l.contains("vpnkit")
    };
    listeners.retain(|(_, cmd, _)| !is_dockerish(cmd));
    if listeners.is_empty() {
        return Vec::new();
    }

    let pids: HashSet<u32> = listeners.iter().map(|(pid, _, _)| *pid).collect();
    let cwd_map = pid_cwds(&pids);
    let home = dirs::home_dir()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_default();

    // OS-assigned ephemeral ports (extension hosts, IPC sockets) are not
    // dev servers anyone would open in a browser.
    const EPHEMERAL_PORT_START: u16 = 49152;

    let mut dedupe: HashSet<(u16, String, String)> = HashSet::new();
    let mut result = Vec::new();
    for (pid, process, port) in listeners {
        if port >= EPHEMERAL_PORT_START {
            continue;
        }
        let Some(cwd) = cwd_map.get(&pid) else {
            continue;
        };
        // Dev servers run from a project dir under $HOME; system daemons
        // don't, and idle GUI apps (Finder, chat clients) sit at $HOME itself.
        if home.is_empty() || cwd == &home || !cwd.starts_with(&home) {
            continue;
        }
        if dedupe.insert((port, process.clone(), cwd.clone())) {
            result.push(BareServer {
                pid,
                process,
                port,
                cwd: cwd.clone(),
            });
        }
    }
    result.sort_by_key(|b| b.port);
    result
}

/// Batch-resolve cwd for a set of pids via `lsof -a -d cwd -p <list> -Fpn`.
fn pid_cwds(pids: &HashSet<u32>) -> HashMap<u32, String> {
    let list = pids
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let output = match Command::new("lsof")
        .args(["-a", "-d", "cwd", "-p", &list, "-Fpn"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return HashMap::new(),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut map = HashMap::new();
    let mut cur_pid: u32 = 0;
    for line in stdout.lines() {
        match line.as_bytes().first() {
            Some(b'p') => cur_pid = line[1..].parse().unwrap_or(0),
            Some(b'n') => {
                if cur_pid != 0 {
                    map.insert(cur_pid, line[1..].to_string());
                }
            }
            _ => {}
        }
    }
    map
}

// ── Snapshot cache + polling ────────────────────────────────────────

static SNAPSHOT: LazyLock<Mutex<Option<InfraSnapshot>>> = LazyLock::new(|| Mutex::new(None));

/// Run a full scan and refresh the cache. Blocks on `docker ps` + `lsof`
/// (typically a few hundred ms) — call from a background thread.
pub fn scan() -> InfraSnapshot {
    let (compose_projects, standalone_containers) = scan_docker();
    let bare_servers = scan_bare_servers();
    let snapshot = InfraSnapshot {
        compose_projects,
        standalone_containers,
        bare_servers,
    };
    if let Ok(mut guard) = SNAPSHOT.lock() {
        *guard = Some(snapshot.clone());
    }
    snapshot
}

/// Return the cached snapshot; falls back to a blocking scan on first call
/// (before the polling thread has produced one).
pub fn current_snapshot() -> InfraSnapshot {
    if let Ok(guard) = SNAPSHOT.lock() {
        if let Some(s) = guard.as_ref() {
            return s.clone();
        }
    }
    scan()
}

/// Background scanner: refresh every 10s, and on change emit the
/// `infra-updated` Tauri event + broadcast to WebSocket clients —
/// the same dual-channel pattern as the session polling loop.
#[cfg(all(not(mobile), feature = "gui"))]
pub fn start_infra_polling(
    app: tauri::AppHandle,
    infra_tx: tokio::sync::broadcast::Sender<String>,
) {
    use tauri::Emitter;

    std::thread::spawn(move || {
        let interval = std::time::Duration::from_secs(10);
        let mut prev_json: Option<String> = None;
        loop {
            let snapshot = scan();
            if let Ok(json) = serde_json::to_string(&snapshot) {
                if prev_json.as_deref() != Some(json.as_str()) {
                    if let Err(e) = app.emit("infra-updated", &snapshot) {
                        crate::debug_log::log_error(&format!(
                            "Failed to emit infra-updated: {}",
                            e
                        ));
                    }
                    let _ = infra_tx.send(json.clone());
                    prev_json = Some(json);
                }
            }
            std::thread::sleep(interval);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ports_published_ipv4_ipv6_dedupes() {
        let ports = parse_ports("0.0.0.0:15432->5432/tcp, [::]:15432->5432/tcp");
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].host_port, 15432);
        assert_eq!(ports[0].container_port, 5432);
        assert_eq!(ports[0].protocol, "tcp");
    }

    #[test]
    fn parse_ports_skips_unpublished() {
        assert!(parse_ports("6379/tcp").is_empty());
        assert!(parse_ports("").is_empty());
    }

    #[test]
    fn parse_ports_multiple_mappings_sorted() {
        let ports =
            parse_ports("0.0.0.0:9001->9001/tcp, 0.0.0.0:9000->9000/tcp, [::]:9000->9000/tcp");
        assert_eq!(
            ports.iter().map(|p| p.host_port).collect::<Vec<_>>(),
            vec![9000, 9001]
        );
    }

    #[test]
    fn parse_ports_udp_protocol() {
        let ports = parse_ports("0.0.0.0:4317->4317/udp");
        assert_eq!(ports[0].protocol, "udp");
    }

    #[test]
    fn scan_smoke() {
        // Environment-dependent (like test_detect_and_enrich_sessions):
        // prints whatever infrastructure is running on this machine.
        let snap = scan();
        println!(
            "compose projects: {}, standalone: {}, bare servers: {}",
            snap.compose_projects.len(),
            snap.standalone_containers.len(),
            snap.bare_servers.len()
        );
        println!("{}", serde_json::to_string_pretty(&snap).unwrap());
    }
}
