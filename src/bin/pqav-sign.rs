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
use sha2::Digest;
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

struct Firmante {
    sk: SigningKey<MlDsa44>,
    kid: [u8; 8],
    stream_id: [u8;16],
    counter: u64,
    prev: [u8; 32],
    cc: u8,
    anchor_pid: u16,
    mapa: Vec<Component>,
    video_pid: u16,
    audio_pid: Option<u16>,
    abierto: Interval,
    vistas: HashSet<(u8, u64)>,
    cola: VecDeque<VecDeque<[u8;188]>>,
    pos_entradas: VecDeque<u64>,
    payload_sizes: Vec<usize>,
    sign_us: Vec<u64>,
    video_units_count: u64,
    audio_units_count: u64,
    cose_sizes: Vec<usize>,
    pkt_counts: Vec<usize>,
    insert_delays: Vec<f64>,
    null_packets_used: u64,
    appended_packets: u64,
    bitrate: u64,
}

impl Firmante {
    fn procesar_pes(&mut self, pid: u16, raw: RawPes, pos: u64) -> Result<(),SignError> {
	let is_video = pid == self.video_pid;
	let p_name = if is_video { "video" } else { "audio" };
	let pes = parse_pes(&raw).map_err(|e| SignError::Ts(e, raw.first_packet))?;
	let pts = pes.pts.ok_or(SignError::SinPts(p_name, raw.first_packet))?;

	let mut unidades = Vec::new();
	if is_video {
	    let hash = hash_video(&pes.payload).map_err(|e| SignError::H264(e,pos))?;
	    unidades.push(Unit { comp: 0, pts, hash});
	} else {
	    let tramas = split_adts(&pes.payload).map_err(|e| SignError::Adts(e, pos))?;
	    for (k, t) in tramas.iter().enumerate() {
		let u_pts = (pts + 120 * k as u64) % (1 << 33);
		let hash = hash_audio(t);
		unidades.push(Unit { comp: 1, pts: u_pts, hash });
	    }
	}
	
	for u in unidades {
	    if self.vistas.contains(&(u.comp, u.pts)) {
		return Err(SignError::Repetida { comp: u.comp, pts: u.pts });
	    }
	    if u.comp == 0 && self.abierto.video_count(0) == 6 {
		self.cerrar_intervalo(false, pos)?;
	    }
	    self.abierto.units.push(u);
	    self.vistas.insert((u.comp, u.pts));
	    if u.comp == 0 {
		self.video_units_count += 1;
	    } else {
	    	self.audio_units_count += 1;
	    }
	}
	Ok(())	
    }

    fn cerrar_intervalo(&mut self, is_final: bool, pos_entrada: u64) -> Result<(), SignError> {
	let base = self.abierto.base().map_err(|e| SignError::Units(e, pos_entrada))?;
	let mut units = Vec::new();
	for u in &self.abierto.units {
	    let r = self.abierto.rel(base, u).map_err(|e| SignError::Units(e, pos_entrada))?;
	    units.push((u.comp, r, u.hash));
	}

	let p = AnchorPayload {
	    stream_id: self.stream_id,
	    counter: self.counter,
	    prev: self.prev,
	    components: map_tuples(&self.mapa),
	    units,
	    is_final,
	};

	let carga = encode(&p)?;
	self.payload_sizes.push(carga.len());

	let t0 = Instant::now();
	let cose = cose::sign(&self.sk, &self.kid, &carga)?;
	self.sign_us.push(t0.elapsed().as_micros() as u64);
	self.cose_sizes.push(cose.len());

	let mut hasher = sha2::Sha256::new();
	sha2::Digest::update(&mut hasher, &cose);
	self.prev.copy_from_slice(&hasher.finalize());
	self.counter += 1;

	let pes = anchor_pes(&cose, base);
	let paquetes = packetize(&pes, self.anchor_pid, &mut self.cc);
	self.pkt_counts.push(paquetes.len());

	let deque: VecDeque<[u8; 188]> = paquetes.into_iter().collect();
	self.cola.push_back(deque);
	self.pos_entradas.push_back(pos_entrada);

	if !is_final && self.cola.len() > 3 {
	    let t_s = (pos_entrada as f64 * 188.0 * 8.0) / self.bitrate as f64;
	    let nulos_kbps = if t_s > 0.0 {
		(self.null_packets_used as f64 * 188.0 * 8.0 / 1000.0) / t_s
	    } else {
		0.0
	    };
	    return Err(SignError::Hueco(nulos_kbps as u64));	    
	}
	self.abierto.units.clear();
	Ok(())
    }
}

fn main() -> std::process::ExitCode {
    std::process::ExitCode::SUCCESS
}

fn run(_args: Args) -> Result<(), SignError> {
    Ok(())
}
