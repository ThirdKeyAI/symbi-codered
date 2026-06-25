//! Scanner-sidecar client.
//!
//! Invokes scanners by running `docker exec <container> scan` and piping
//! a JSON request on stdin.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Write;
use std::process::{Command, Stdio};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScannerClientError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("docker exec exited {0}: {1}")]
    DockerExec(i32, String),
    #[error("scanner returned error: {0}")]
    Scanner(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerRequest {
    pub tool: String,
    pub target_dir: String,
    #[serde(default)]
    pub extra_args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerResponse {
    pub tool: String,
    pub ok: bool,
    pub exit_code: i32,
    #[serde(default)]
    pub cmd: String,
    #[serde(default)]
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
    #[serde(default)]
    pub raw_json: Option<Value>,
    #[serde(default)]
    pub error: Option<String>,
}

pub fn run_scanner(
    container_name: &str,
    req: &ScannerRequest,
) -> Result<ScannerResponse, ScannerClientError> {
    let req_json = serde_json::to_string(req)?;
    let mut child = Command::new("docker")
        .args(["exec", "-i", container_name, "/usr/local/bin/entrypoint", "scan"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    child.stdin.as_mut().unwrap().write_all(req_json.as_bytes())?;
    drop(child.stdin.take());

    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(ScannerClientError::DockerExec(
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    let resp: ScannerResponse = serde_json::from_slice(&output.stdout)?;
    if let Some(err) = &resp.error {
        return Err(ScannerClientError::Scanner(err.clone()));
    }
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scanner_request_serializes_with_expected_keys() {
        let req = ScannerRequest {
            tool: "bandit".into(),
            target_dir: "/repo".into(),
            extra_args: vec!["-q".into()],
        };
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains(r#""tool":"bandit""#));
        assert!(s.contains(r#""target_dir":"/repo""#));
        assert!(s.contains(r#""extra_args":["-q"]"#));
    }

    #[test]
    fn scanner_response_deserializes_with_raw_json() {
        let body = r#"{
            "tool": "semgrep",
            "ok": true,
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "raw_json": {"results": []}
        }"#;
        let resp: ScannerResponse = serde_json::from_str(body).unwrap();
        assert_eq!(resp.tool, "semgrep");
        assert!(resp.ok);
        assert!(resp.raw_json.is_some());
    }
}
