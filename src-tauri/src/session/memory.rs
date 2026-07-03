use serde::Serialize;
use std::fs;

/// A single memory file (e.g., MEMORY.md, profile.md)
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryFile {
    pub filename: String,
    pub content: String,
}

/// All memory files for a single project
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectMemory {
    /// Human-readable project name (last path segment, e.g. "c9watch")
    pub project_name: String,
    /// Decoded full project path (e.g. "/Users/liminchen/Documents/GitHub/c9watch")
    pub project_path: String,
    /// Absolute path to the memory directory (for "Reveal in Finder")
    pub memory_dir_path: String,
    /// Memory files found in this project
    pub files: Vec<MemoryFile>,
}

/// Decode a Claude projects directory name back to a real path.
/// e.g. "-Users-liminchen-Documents-GitHub-c9watch" → "/Users/liminchen/Documents/GitHub/c9watch"
fn decode_project_dir(dir_name: &str) -> String {
    if dir_name.starts_with('-') {
        format!("/{}", dir_name[1..].replace('-', "/"))
    } else {
        dir_name.replace('-', "/")
    }
}

/// Scan ~/.claude/projects/*/memory/*.md and return all memory files grouped by project.
pub fn get_memory_files() -> Result<Vec<ProjectMemory>, String> {
    let home_dir = dirs::home_dir().ok_or("Failed to get home directory")?;
    let projects_dir = home_dir.join(".claude").join("projects");

    if !projects_dir.exists() {
        return Ok(Vec::new());
    }

    let entries = fs::read_dir(&projects_dir)
        .map_err(|e| format!("Failed to read projects directory: {}", e))?;

    let mut results: Vec<ProjectMemory> = Vec::new();

    for entry in entries.flatten() {
        let project_dir = entry.path();
        if !project_dir.is_dir() {
            continue;
        }

        let memory_dir = project_dir.join("memory");
        if !memory_dir.is_dir() {
            continue;
        }

        let dir_name = project_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();

        let decoded_path = decode_project_dir(&dir_name);
        let project_name = decoded_path
            .rsplit('/')
            .find(|s| !s.is_empty())
            .unwrap_or(&dir_name)
            .to_string();

        let mut files: Vec<MemoryFile> = Vec::new();

        if let Ok(mem_entries) = fs::read_dir(&memory_dir) {
            for mem_entry in mem_entries.flatten() {
                let file_path = mem_entry.path();
                if file_path.extension().and_then(|e| e.to_str()) == Some("md") {
                    let filename = file_path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("")
                        .to_string();

                    if let Ok(content) = fs::read_to_string(&file_path) {
                        files.push(MemoryFile { filename, content });
                    }
                }
            }
        }

        if !files.is_empty() {
            // Sort: MEMORY.md first, then alphabetical
            files.sort_by(|a, b| {
                let a_is_main = a.filename == "MEMORY.md";
                let b_is_main = b.filename == "MEMORY.md";
                b_is_main.cmp(&a_is_main).then(a.filename.cmp(&b.filename))
            });

            results.push(ProjectMemory {
                project_name,
                project_path: decoded_path,
                memory_dir_path: memory_dir.to_string_lossy().to_string(),
                files,
            });
        }
    }

    // Sort projects alphabetically by name
    results.sort_by(|a, b| {
        a.project_name
            .to_lowercase()
            .cmp(&b.project_name.to_lowercase())
    });

    Ok(results)
}
