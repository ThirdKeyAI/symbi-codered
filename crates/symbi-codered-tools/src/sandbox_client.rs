//! Sandbox client — `docker exec` wrapper for the python-sandbox sidecar.

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::process::{Command, Stdio};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SandboxClientError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("docker exec exited {0}: {1}")]
    DockerExec(i32, String),
    #[error("sandbox error: {0}")]
    Sandbox(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxRequest {
    pub script: String,
    #[serde(default)]
    pub timeout_seconds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxResponse {
    pub ok: bool,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub verdict: String,
    #[serde(default)]
    pub error: Option<String>,
}

pub fn run_reproducer(
    container_name: &str,
    req: &SandboxRequest,
) -> Result<SandboxResponse, SandboxClientError> {
    let req_json = serde_json::to_string(req)?;
    let mut child = Command::new("docker")
        .args(["exec", "-i", container_name, "/usr/local/bin/entrypoint", "run"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child.stdin.as_mut().unwrap().write_all(req_json.as_bytes())?;
    drop(child.stdin.take());
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(SandboxClientError::DockerExec(
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    let resp: SandboxResponse = serde_json::from_slice(&output.stdout)?;
    if let Some(err) = &resp.error {
        return Err(SandboxClientError::Sandbox(err.clone()));
    }
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_request_with_expected_keys() {
        let req = SandboxRequest { script: "print('REPRODUCED')".into(), timeout_seconds: 10 };
        let j = serde_json::to_value(&req).unwrap();
        assert!(j.get("script").is_some());
        assert!(j.get("timeout_seconds").is_some());
    }
}
