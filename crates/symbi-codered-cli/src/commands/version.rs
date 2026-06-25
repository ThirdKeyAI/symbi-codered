use anyhow::Result;

pub fn print() -> Result<()> {
    println!("codered {}", env!("CARGO_PKG_VERSION"));
    println!("symbi-evidence-schema {}",
        symbi_evidence_schema::SCHEMA_VERSION);
    Ok(())
}
