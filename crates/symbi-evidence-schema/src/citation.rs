use serde::{Deserialize, Serialize};

/// One citation backing a pattern_scout finding. The Cedar `citation.cedar`
/// policy rejects any finding whose `citations` array is empty or whose
/// citations don't satisfy one of the three valid shapes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Citation {
    /// (a) interpreting a static-analyzer finding
    Analyzer {
        finding_id: String,
    },
    /// (b) line-numbered code reference
    Code {
        file_path: String,
        line_start: u32,
        line_end: u32,
    },
    /// (c) explicit hypothesis flagged for poc_forge
    Hypothesis {
        hypothesis_id: String,
        intended_poc: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyzer_citation_roundtrip() {
        let c = Citation::Analyzer { finding_id: "F-0042".into() };
        let s = serde_json::to_string(&c).unwrap();
        let back: Citation = serde_json::from_str(&s).unwrap();
        assert_eq!(c, back);
        assert!(s.contains(r#""type":"analyzer""#));
    }

    #[test]
    fn code_citation_roundtrip() {
        let c = Citation::Code {
            file_path: "src/auth.py".into(),
            line_start: 88,
            line_end: 95,
        };
        let s = serde_json::to_string(&c).unwrap();
        let back: Citation = serde_json::from_str(&s).unwrap();
        assert_eq!(c, back);
        assert!(s.contains(r#""type":"code""#));
    }

    #[test]
    fn hypothesis_citation_roundtrip() {
        let c = Citation::Hypothesis {
            hypothesis_id: "H-0007".into(),
            intended_poc: "boolean-blind SQLi via ORDER BY".into(),
        };
        let s = serde_json::to_string(&c).unwrap();
        let back: Citation = serde_json::from_str(&s).unwrap();
        assert_eq!(c, back);
        assert!(s.contains(r#""type":"hypothesis""#));
    }
}
