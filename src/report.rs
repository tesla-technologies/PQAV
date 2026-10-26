// SPDX-License-Identifier: MIT OR Apache-2.0
//src/report.rs
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    FirmaInvalida,
    Empalme,
    MapaAlterado,
    Manipulado,
    Incompleto,
    Autentico,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Global {
    Autentico,
    Rechazado,
    ErrorEntrada,
    SinFirmar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct UnitRef {
    pub comp: u8,
    pub pts: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IntervalReport {
    pub index: usize,
    pub counter: Option<u64>,
    pub base: Option<u64>,
    pub verdict: Verdict,
    pub detail: Option<String>,
    pub gap_before: u64,
    pub video_ok: usize,
    pub video_total: usize,
    pub audio_ok: usize,
    pub audio_total: usize,
    pub modified: Vec<UnitRef>,
    pub missing: Vec<UnitRef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Received {
    pub video: usize,
    pub audio: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Percentiles {
    pub p50: u64,
    pub p99: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub global: Global,
    pub reasons: Vec<String>,
    pub error: Option<String>,
    pub anchors: usize,
    pub intervals: Vec<IntervalReport>,
    pub received_units: Received,
    pub unsigned_units: usize,
    pub unreadable_pes: usize,
    pub final_anchor: bool,
    pub verify_us: Option<Percentiles>,
}

pub fn percentile(sorted: &[u64], p: u32) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let n = sorted.len() as f64;
    let idx = (p as f64 / 100.0 * n).ceil() as usize;
    let i = if idx == 0 { 0 } else { idx - 1 };
    Some(sorted[i])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn m9_json_y_percentiles() {
        let v: Vec<u64> = (1..=250).collect();
        assert_eq!(percentile(&v, 50), Some(125));
        assert_eq!(percentile(&v, 99), Some(248));
        assert_eq!(percentile(&[], 50), None);
        assert!(
            Verdict::FirmaInvalida < Verdict::Empalme && Verdict::Incompleto < Verdict::Autentico
        );
        let i = IntervalReport {
            index: 0,
            counter: Some(0),
            base: Some(126_000),
            verdict: Verdict::Autentico,
            detail: None,
            gap_before: 0,
            video_ok: 6,
            video_total: 6,
            audio_ok: 0,
            audio_total: 0,
            modified: vec![],
            missing: vec![],
        };
        let r = Report {
            global: Global::Autentico,
            reasons: vec![],
            error: None,
            anchors: 1,
            intervals: vec![i],
            received_units: Received { video: 6, audio: 0 },
            unsigned_units: 0,
            unreadable_pes: 0,
            final_anchor: true,
            verify_us: Some(Percentiles { p50: 0, p99: 0 }),
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.starts_with(r#"{"global":"AUTENTICO","reasons":[],"error":null,"anchors":1,"#));
        assert!(s.contains(r#""verdict":"AUTENTICO","detail":null,"gap_before":0"#));
    }
}
