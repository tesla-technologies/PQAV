// SPDX-License-Identifier: MIT OR Apache-2.0
use clap::Parser;
use pqav::adts::{hash_audio, split_adts, AdtsError};
use pqav::anchor::{encode, AnchorError, AnchorPayload};
use pqav::cose::{self, CoseError};
use pqav::h264::{hash_video, H264Error};
use pqav::keys::{leer_seed, KeyError};
use pqav::ts::{
    anchor_pes, packetize, parse_packet, parse_pat, parse_pes, parse_pmt, PesAssembler, RawPes,
    SectionAssembler, TsError, NULL_PID, TS,
};
use pqav::units::{component_map, find_anchor_pid, map_tuples, Component, Interval, Unit, UnitsError};
use ml_dsa::{MlDsa44, SigningKey};
use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::time::Instant;

fn parse_pid(s: &str) -> Result<u16, String> {
    let p = if s.starts_with("0x") {
        u16::from_str_radix(&s[2..], 16).map_err(|_| "PID inválido")?
    } else {
        s.parse::<u16>().map_err(|_| "PID inválido")?
    };
    if !(0x0010..=0x1FFE).contains(&p) {
        return Err(format!("PID 0x{:04X} fuera de rango", p));
    }
    Ok(p)
}

#[derive(clap::Parser, Debug)]
#[command(version, about = "Firma un TS grabado (H.264 + AAC) con ML-DSA-44")]
struct Args {
    #[arg(long, value_name = "FICHERO")]
    key: PathBuf,
    #[arg(long = "in", value_name = "FICHERO")]
    input: PathBuf,
    #[arg(long, value_name = "FICHERO")]
    out: PathBuf,
    #[arg(long, value_name = "PID", default_value = "0x1FF0", value_parser = parse_pid)]
    anchor_pid: u16,
    #[arg(long, value_name = "BIT/S", default_value_t = 8_000_000)]
    bitrate: u64,
    #[arg(long, value_name = "FICHERO")]
    stats: Option<PathBuf>,
    #[arg(long, value_name = "COMP:PTS")]
    debug_unit: Option<String>,
}

#[derive(Debug, thiserror::Error)]
enum SignError {
    #[error("{0}")]
    Clave(#[from] KeyError),
    #[error("no se puede leer {0}: {1}")]
    Leer(String, std::io::Error),
    #[error("no se puede escribir {0}: {1}")]
    Escribir(String, std::io::Error),
    #[error("el fichero no mide un múltiplo de 188 bytes")]
    NoMultiplo,
    #[error("{0} (paquete {1})")]
    Ts(TsError, u64),
    #[error("{0} en la tabla del PID 0x{1:04X} (paquete {2})")]
    Tabla(TsError, u16, u64),
    #[error("{0} (paquete {1})")]
    H264(H264Error, u64),
    #[error("{0} (paquete {1})")]
    Adts(AdtsError, u64),
    #[error("{0} (paquete {1})")]
    Units(UnitsError, u64),
    #[error("{0}")]
    Anchor(#[from] AnchorError),
    #[error("{0}")]
    Cose(#[from] CoseError),
    #[error("no se ha encontrado la PAT o la PMT")]
    SinTablas,
    #[error("la PMT cambia a mitad del fichero (paquete {0})")]
    PmtCambia(u64),
    #[error("el fichero ya está firmado")]
    YaFirmado,
    #[error("PES de {0} sin PTS (paquete {1})")]
    SinPts(&'static str, u64),
    #[error("unidad repetida: componente {comp} y PTS {pts}")]
    Repetida { comp: u8, pts: u64 },
    #[error("no hay unidades que firmar")]
    SinUnidades,
    #[error("hueco de nulos insuficiente: más de 3 anclas esperando (nulos medidos: {0} kb/s)")]
    Hueco(u64),
}

#[derive(serde::Serialize)]
struct Stats {
    anchors: u64,
    video_units: u64,
    audio_units: u64,
    payload_bytes: StatCalc<usize>,
    cose_bytes: StatCalc<usize>,
    ts_packets_per_anchor: StatCalcF,
    appended_packets: u64,
    insert_delay_ms: PercentilesF,
    sign_us: PercentilesU,
    input_packets: u64,
    null_packets_in: u64,
    null_packets_used: u64,
    bitrate_bps: u64,
}

#[derive(serde::Serialize)]
struct StatCalc<T> { mean: f64, min: T, max: T }
#[derive(serde::Serialize)]
struct StatCalcF { mean: f64, min: usize, max: usize }
#[derive(serde::Serialize)]
struct PercentilesF { p50: f64, p99: f64 }
#[derive(serde::Serialize)]
struct PercentilesU { p50: u64, p99: u64, samples: u64 }

fn calc_stat(v: &[usize]) -> StatCalc<usize> {
    if v.is_empty() { return StatCalc { mean: 0.0, min: 0, max: 0 }; }
    let min = *v.iter().min().unwrap();
    let max = *v.iter().max().unwrap();
    let mean = v.iter().sum::<usize>() as f64 / v.len() as f64;
    StatCalc { mean: (mean * 100.0).round() / 100.0, min, max }
}
fn calc_stat_f(v: &[usize]) -> StatCalcF {
    if v.is_empty() { return StatCalcF { mean: 0.0, min: 0, max: 0 }; }
    let min = *v.iter().min().unwrap();
    let max = *v.iter().max().unwrap();
    let mean = v.iter().sum::<usize>() as f64 / v.len() as f64;
    StatCalcF { mean: (mean * 100.0).round() / 100.0, min, max }
}
fn calc_perc_f(mut v: Vec<f64>) -> PercentilesF {
    if v.is_empty() { return PercentilesF { p50: 0.0, p99: 0.0 }; }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len() as f64;
    let i50 = (0.50 * n).ceil() as usize - 1;
    let i99 = (0.99 * n).ceil() as usize - 1;
    PercentilesF { p50: (v[i50] * 10.0).round() / 10.0, p99: (v[i99] * 10.0).round() / 10.0 }
}
fn calc_perc_u(mut v: Vec<u64>) -> PercentilesU {
    let s = v.len() as u64;
    if v.is_empty() { return PercentilesU { p50: 0, p99: 0, samples: s }; }
    v.sort_unstable();
    let n = v.len() as f64;
    let i50 = (0.50 * n).ceil() as usize - 1;
    let i99 = (0.99 * n).ceil() as usize - 1;
    PercentilesU { p50: v[i50], p99: v[i99], samples: s }
}

fn main() -> std::process::ExitCode {
    std::process::ExitCode::SUCCESS
}

fn run(_args: Args) -> Result<(), SignError> {
    Ok(())
}
