//! Specifier native tool.

use chrono::Utc;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;
use thiserror::Error;
use uuid::Uuid;

use symbi_codered_core::db;
use symbi_codered_core::signing;
use symbi_evidence_schema::ThreatModel;

#[derive(Debug, Error)]
pub enum SpecifierError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("toml: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("db: {0}")]
    Db(#[from] db::DbError),
    #[error("signing: {0}")]
    Signing(#[from] signing::SigningError),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScopeOverrides {
    #[serde(default)] pub in_scope_paths: Vec<String>,
    #[serde(default)] pub exclude_paths: Vec<String>,
    #[serde(default)] pub in_scope_languages: Vec<String>,
    #[serde(default)] pub out_of_scope_endpoints: Vec<String>,
    #[serde(default)] pub sources: Vec<String>,
    #[serde(default)] pub sinks: Vec<String>,
    /// Function names that count as authorization / sanitization /
    /// validation guards. taint_tracer classifies a source→sink chain
    /// as `guarded` if any edge on the path involves one of these
    /// names; otherwise as `unguarded`. Used to surface missing-auth
    /// bugs (e.g., handler→data-layer chains with no authz check).
    #[serde(default)] pub guards: Vec<String>,
}

impl ScopeOverrides {
    pub fn load_from_toml(path: &Path) -> Result<Self, SpecifierError> {
        let body = std::fs::read_to_string(path)?;
        let overrides: ScopeOverrides = toml::from_str(&body)?;
        Ok(overrides)
    }
}

pub fn pin_threat_model(
    conn: &Connection,
    engagement_id: Uuid,
    target_dir: &Path,
    overrides: ScopeOverrides,
    keys_dir: Option<&Path>,
) -> Result<ThreatModel, SpecifierError> {
    let lang_rows = db::list_repo_facts(conn, engagement_id, "language")?;
    let mut detected_languages: Vec<String> = lang_rows
        .iter()
        .filter_map(|row| {
            let v: Value = serde_json::from_str(row).ok()?;
            v.get("name").and_then(|n| n.as_str()).map(String::from)
        })
        .collect();
    detected_languages.sort();
    detected_languages.dedup();

    let in_scope_languages = if overrides.in_scope_languages.is_empty() {
        detected_languages
    } else {
        overrides.in_scope_languages.clone()
    };

    let (mut sources, mut sinks) = (overrides.sources.clone(), overrides.sinks.clone());
    let lang_set: std::collections::HashSet<&str> =
        in_scope_languages.iter().map(|s| s.as_str()).collect();
    if sources.is_empty() {
        if lang_set.contains("python") {
            sources.extend([
                "request.args".into(),
                "request.form".into(),
                "request.json".into(),
                "request.values".into(),
            ]);
        }
        if lang_set.contains("rust") {
            // Axum/actix-style extractors + raw stdin/env. Taint_tracer matches
            // these as substrings against qualified dataflow_edges symbols.
            sources.extend([
                "axum::extract::Query".into(),
                "axum::extract::Path".into(),
                "axum::extract::Json".into(),
                "axum::extract::Form".into(),
                "axum::extract::Multipart".into(),
                "actix_web::web::Query".into(),
                "actix_web::web::Json".into(),
                "actix_web::web::Form".into(),
                "std::env::var".into(),
                "std::io::stdin".into(),
            ]);
        }
        if lang_set.contains("typescript") || lang_set.contains("javascript") {
            // Express / Hono / Fastify / Koa request surfaces.
            sources.extend([
                "req.query".into(),
                "req.body".into(),
                "req.params".into(),
                "req.headers".into(),
                "c.req.query".into(),
                "c.req.json".into(),
                "request.json".into(),
            ]);
        }
        if lang_set.contains("go") {
            // gRPC + net/http handler request surfaces. Go handler args
            // are typically `req *FooRequest` where FooRequest is a pb
            // type — taint_tracer's substring match catches `req.` field
            // access via the chunker-emitted `file:fn:req.FieldName`
            // edges.
            sources.extend([
                "req.".into(),                  // generic gRPC handler req struct field access
                "request.".into(),
                "r.URL.Query".into(),
                "r.FormValue".into(),
                "r.PostFormValue".into(),
                "r.Body".into(),
                "r.Header".into(),
                "ctx.UserValue".into(),
                "os.Getenv".into(),
            ]);
        }
        if lang_set.contains("php") {
            // PHP request surfaces are superglobals (array subscripts); the
            // dataflow extractor emits the base superglobal as from_symbol.
            sources.extend([
                "$_GET".into(),
                "$_POST".into(),
                "$_REQUEST".into(),
                "$_COOKIE".into(),
                "$_SERVER".into(),
                "$_FILES".into(),
                "php://input".into(),
            ]);
        }
    }
    if sinks.is_empty() {
        if lang_set.contains("python") {
            sinks.extend([
                "cursor.execute".into(),
                "subprocess.run".into(),
                "subprocess.Popen".into(),
                "os.system".into(),
                "eval".into(),
                "pickle.loads".into(),
            ]);
        }
        if lang_set.contains("rust") {
            sinks.extend([
                // Process launch — CWE-78 family
                "std::process::Command::new".into(),
                "Command::new".into(),
                "tokio::process::Command::new".into(),
                // Raw SQL — CWE-89 family
                "sqlx::query".into(),
                "rusqlite::Connection::execute".into(),
                "diesel::sql_query".into(),
                // Filesystem — CWE-22 family
                "std::fs::read".into(),
                "std::fs::write".into(),
                "std::fs::File::open".into(),
                // Deserialization — CWE-502 family (not in poc_forge filter today, but useful)
                "serde_json::from_str".into(),
                "bincode::deserialize".into(),
            ]);
        }
        if lang_set.contains("typescript") || lang_set.contains("javascript") {
            sinks.extend([
                "child_process.exec".into(),
                "child_process.execSync".into(),
                "child_process.spawn".into(),
                "eval".into(),
                "Function".into(),       // new Function(...) code-injection
                "innerHTML".into(),
                "outerHTML".into(),
                "document.write".into(),
                "fs.readFile".into(),
                "fs.writeFile".into(),
            ]);
        }
        if lang_set.contains("go") {
            sinks.extend([
                // Process launch — CWE-78 family
                "exec.Command".into(),
                "exec.CommandContext".into(),
                // Raw SQL — CWE-89 family. The chunker-emitted symbols
                // capture the rightmost call: `db.Query`, `.QueryRow`,
                // `.Exec`, plus goqu / sqlx / gorm / pgx surfaces.
                "db.Query".into(),
                "db.Exec".into(),
                "db.QueryRow".into(),
                ".Query(".into(),
                ".Exec(".into(),
                "sqlx.Query".into(),
                "gorm.Raw".into(),
                "pgx.Query".into(),
                "goqu.L".into(),       // goqu raw-literal escape hatch
                // Filesystem — CWE-22 family
                "os.Open".into(),
                "os.Create".into(),
                "os.ReadFile".into(),
                "ioutil.ReadFile".into(),
                "filepath.Join".into(),
                // HTTP egress — SSRF (CWE-918)
                "http.Get".into(),
                "http.Post".into(),
                "http.NewRequest".into(),
                "(*http.Client).Do".into(),
                "grpc.Dial".into(),
                // Deserialization — CWE-502
                "gob.NewDecoder".into(),
                "yaml.Unmarshal".into(),
            ]);
        }
        if lang_set.contains("php") {
            sinks.extend([
                // SQL — CWE-89. Function-style and method-style (PDO/mysqli).
                "mysqli_query".into(),
                "mysql_query".into(),
                "pg_query".into(),
                "->query".into(),
                "->exec".into(),
                "->prepare".into(),
                // Command exec — CWE-78
                "exec".into(),
                "system".into(),
                "shell_exec".into(),
                "passthru".into(),
                "proc_open".into(),
                "popen".into(),
                // Code eval — CWE-94/95
                "eval".into(),
                "assert".into(),
                // File inclusion / traversal — CWE-98/22
                "include".into(),
                "require".into(),
                "file_get_contents".into(),
                "fopen".into(),
                // Deserialization — CWE-502
                "unserialize".into(),
            ]);
        }
    }

    // Guard call names — function names whose presence on the path
    // between a source and a sink suggests an authz / sanitization /
    // validation step. Used by taint_tracer to classify chains as
    // `guarded_chain` vs `unguarded_chain`; unguarded chains terminating
    // at sensitive sinks are the missing-auth signal. Operators can
    // extend via the scope file.
    let mut guards: Vec<String> = overrides.guards.clone();
    if guards.is_empty() {
        guards.extend([
            // Common authorization helpers across languages
            "Authorize".into(),
            "authorize".into(),
            "CheckAccess".into(),
            "CheckPermission".into(),
            "HasPermission".into(),
            "MustOrg".into(),
            "RequireOrg".into(),
            "WithOrg".into(),
            "Permits".into(),
            "ValidateToken".into(),
            "Authenticate".into(),
        ]);
        if lang_set.contains("python") {
            guards.extend([
                "@login_required".into(),
                "@permission_required".into(),
                "current_user".into(),
                "is_authenticated".into(),
            ]);
        }
        if lang_set.contains("rust") {
            guards.extend([
                "ensure_authorized".into(),
                "must_be_admin".into(),
                "verify_jwt".into(),
            ]);
        }
        if lang_set.contains("go") {
            guards.extend([
                "AuthorizeRequest".into(),
                "ctx.Value(\"org_id\")".into(),
                "verifyOrg".into(),
                "ensureOrgAccess".into(),
                // Context-propagation authz idiom (guards are substring-matched,
                // so these catch the family: WithAuthorizedOrganizationIds,
                // WithAuthorizedAssetId, WithAuthorizationPerformed,
                // WithAuthenticationSource, ...). This is the dominant pattern
                // in Go services that record an authz decision in the request
                // context rather than calling a named gate in the handler body.
                "WithAuthorized".into(),
                "WithAuthorization".into(),
                "WithAuthentication".into(),
            ]);
        }
    }

    let mut tm = BTreeMap::new();
    tm.insert("engagement_id".to_string(), Value::String(engagement_id.to_string()));
    tm.insert("schema_version".to_string(), Value::String("1.0".to_string()));
    tm.insert("target".to_string(),
        Value::String(target_dir.to_string_lossy().into_owned()));
    tm.insert("in_scope_languages".to_string(),
        Value::Array(in_scope_languages.into_iter().map(Value::String).collect()));
    tm.insert("in_scope_paths".to_string(),
        Value::Array(overrides.in_scope_paths.iter().cloned().map(Value::String).collect()));
    tm.insert("exclude_paths".to_string(),
        Value::Array(overrides.exclude_paths.iter().cloned().map(Value::String).collect()));
    tm.insert("out_of_scope_endpoints".to_string(),
        Value::Array(overrides.out_of_scope_endpoints.iter().cloned().map(Value::String).collect()));
    tm.insert("sources".to_string(),
        Value::Array(sources.into_iter().map(Value::String).collect()));
    tm.insert("sinks".to_string(),
        Value::Array(sinks.into_iter().map(Value::String).collect()));
    tm.insert("guards".to_string(),
        Value::Array(guards.into_iter().map(Value::String).collect()));

    let canonical = serde_json::to_string(&tm)?;
    let specifier_hash = ThreatModel::hash_for(&canonical);

    let keypair = match keys_dir {
        Some(dir) => match signing::load_from(dir, engagement_id) {
            Ok(kp) => kp,
            Err(signing::SigningError::Io(_)) => {
                signing::generate_and_persist_in(dir, engagement_id)?
            }
            Err(e) => return Err(e.into()),
        },
        None => match signing::load(engagement_id) {
            Ok(kp) => kp,
            Err(signing::SigningError::Io(_)) => signing::generate_and_persist(engagement_id)?,
            Err(e) => return Err(e.into()),
        },
    };
    let signature = keypair.sign_hex(canonical.as_bytes());

    let tm_row = ThreatModel {
        specifier_hash: specifier_hash.clone(),
        engagement_id,
        canonical_json: canonical,
        signed_at: Utc::now(),
        signature,
    };
    db::insert_threat_model(conn, &tm_row)?;
    Ok(tm_row)
}

pub fn verify_threat_model(
    tm: &ThreatModel,
    keys_dir: Option<&Path>,
) -> Result<(), SpecifierError> {
    let keypair = match keys_dir {
        Some(dir) => signing::load_from(dir, tm.engagement_id)?,
        None => signing::load(tm.engagement_id)?,
    };
    keypair.verify_hex(tm.canonical_json.as_bytes(), &tm.signature)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use symbi_codered_core::db as db_;
    use symbi_evidence_schema::Engagement;
    use tempfile::TempDir;

    // Tests mutate process-global CWD to redirect `.symbiont/keys/`.
    // Serialize them so concurrent test threads don't race on getcwd/chdir.
    static CWD_LOCK: Mutex<()> = Mutex::new(());

    fn fresh_db() -> (TempDir, Connection, Uuid) {
        let dir = TempDir::new().unwrap();
        let conn = db_::init_db(dir.path().join("test.db").to_str().unwrap()).unwrap();
        let e = Engagement::new("acme", "h", "2026-05-22", "2026-05-29");
        let id = e.id;
        db_::insert_engagement(&conn, &e).unwrap();
        db_::insert_repo_fact(&conn, id, "language", r#"{"name":"python"}"#).unwrap();
        (dir, conn, id)
    }

    #[test]
    fn pin_then_verify_roundtrips() {
        let _guard = CWD_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let work = TempDir::new().unwrap();
        let saved = std::env::current_dir().unwrap();
        std::env::set_current_dir(work.path()).unwrap();
        let _restore = scopeguard::guard((), |_| {
            let _ = std::env::set_current_dir(&saved);
        });

        let (_dbdir, conn, eng) = fresh_db();
        let tm = pin_threat_model(
            &conn, eng, work.path(),
            ScopeOverrides::default(),
            None,
        ).unwrap();
        assert_eq!(tm.specifier_hash.len(), 64);
        assert!(!tm.signature.is_empty());
        assert!(tm.canonical_json.contains("\"python\""));
        assert!(tm.canonical_json.contains("\"sources\""));
        assert!(tm.canonical_json.contains("\"cursor.execute\""));

        verify_threat_model(&tm, None).expect("signature must verify");
    }

    #[test]
    fn operator_overrides_replace_detected_languages() {
        let _guard = CWD_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let work = TempDir::new().unwrap();
        let saved = std::env::current_dir().unwrap();
        std::env::set_current_dir(work.path()).unwrap();
        let _restore = scopeguard::guard((), |_| {
            let _ = std::env::set_current_dir(&saved);
        });

        let (_dbdir, conn, eng) = fresh_db();
        let overrides = ScopeOverrides {
            in_scope_languages: vec!["typescript".to_string()],
            ..Default::default()
        };
        let tm = pin_threat_model(&conn, eng, work.path(), overrides, None).unwrap();
        assert!(!tm.canonical_json.contains("\"python\""));
        assert!(tm.canonical_json.contains("\"typescript\""));
    }

    #[test]
    fn php_seeds_default_sources_and_sinks() {
        let _guard = CWD_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let work = TempDir::new().unwrap();
        let saved = std::env::current_dir().unwrap();
        std::env::set_current_dir(work.path()).unwrap();
        let _restore = scopeguard::guard((), |_| {
            let _ = std::env::set_current_dir(&saved);
        });

        let (_dbdir, conn, eng) = fresh_db();
        let overrides = ScopeOverrides {
            in_scope_languages: vec!["php".to_string()],
            ..Default::default()
        };
        let tm = pin_threat_model(&conn, eng, work.path(), overrides, None).unwrap();
        let json = &tm.canonical_json;
        assert!(json.contains("$_GET"), "expected $_GET source in {json}");
        assert!(json.contains("$_POST"), "expected $_POST source");
        assert!(json.contains("mysqli_query"), "expected mysqli_query sink");
        assert!(json.contains("->query"), "expected ->query method sink");
    }
}
