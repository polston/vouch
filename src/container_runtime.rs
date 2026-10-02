//! Cross-Platform Container Runtime Detection & Socket Abstraction (M3.3).
//!
//! Detects active container runtime environments (Docker, Podman, Colima, Lima, Finch, nerdctl)
//! and normalizes host filesystem mount paths across local VM socket boundaries before
//! evaluating them against `write.allow_paths`.

use std::path::{Path, PathBuf};

/// Identified container engine runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerEngine {
    Docker,
    Podman,
    Colima,
    Lima,
    Finch,
    Containerd,
    Unknown(String),
}

/// Metadata describing an active container runtime endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerRuntimeInfo {
    pub engine: ContainerEngine,
    pub socket_path: PathBuf,
    pub is_vm_backed: bool,
}

impl ContainerRuntimeInfo {
    pub fn new(engine: ContainerEngine, socket_path: PathBuf, is_vm_backed: bool) -> Self {
        Self {
            engine,
            socket_path,
            is_vm_backed,
        }
    }
}

/// Detect the active container runtime by inspecting environment variables and standard socket paths.
pub fn detect_active_runtime(home: &str) -> Option<ContainerRuntimeInfo> {
    // 1. Environment variable overrides take precedence
    if let Ok(val) = std::env::var("DOCKER_HOST") {
        if let Some(path) = parse_socket_url(&val) {
            let engine = if path.to_string_lossy().contains("colima") {
                ContainerEngine::Colima
            } else if path.to_string_lossy().contains("lima") {
                ContainerEngine::Lima
            } else {
                ContainerEngine::Docker
            };
            return Some(ContainerRuntimeInfo::new(engine, path, true));
        }
    }

    if let Ok(val) = std::env::var("CONTAINER_HOST") {
        if let Some(path) = parse_socket_url(&val) {
            return Some(ContainerRuntimeInfo::new(ContainerEngine::Podman, path, true));
        }
    }

    let home_path = Path::new(home);

    // 2. Colima sockets (macOS/Linux)
    let colima_default = home_path.join(".colima/default/docker.sock");
    if colima_default.exists() {
        return Some(ContainerRuntimeInfo::new(ContainerEngine::Colima, colima_default, true));
    }
    let colima_bare = home_path.join(".colima/docker.sock");
    if colima_bare.exists() {
        return Some(ContainerRuntimeInfo::new(ContainerEngine::Colima, colima_bare, true));
    }

    // 3. Finch socket (macOS/Linux)
    let finch_sock = home_path.join(".finch/finch.sock");
    if finch_sock.exists() {
        return Some(ContainerRuntimeInfo::new(ContainerEngine::Finch, finch_sock, true));
    }

    // 4. Lima sockets
    let lima_default = home_path.join(".lima/default/sock/docker.sock");
    if lima_default.exists() {
        return Some(ContainerRuntimeInfo::new(ContainerEngine::Lima, lima_default, true));
    }

    // 5. Podman rootless socket
    let podman_sock = home_path.join(".local/share/containers/podman/machine/qemu/podman.sock");
    if podman_sock.exists() {
        return Some(ContainerRuntimeInfo::new(ContainerEngine::Podman, podman_sock, true));
    }

    // 6. Standard system Docker socket
    let system_docker = PathBuf::from("/var/run/docker.sock");
    if system_docker.exists() {
        return Some(ContainerRuntimeInfo::new(ContainerEngine::Docker, system_docker, false));
    }

    None
}

/// Normalizes a container volume host path argument across runtime conventions.
pub fn normalize_mount_source(raw_source: &str, home: &str) -> String {
    if raw_source.starts_with('~') {
        return format!("{}{}", home, &raw_source[1..]);
    }
    raw_source.to_string()
}

fn parse_socket_url(url: &str) -> Option<PathBuf> {
    if let Some(stripped) = url.strip_prefix("unix://") {
        Some(PathBuf::from(stripped))
    } else if url.starts_with('/') {
        Some(PathBuf::from(url))
    } else {
        None
    }
}
