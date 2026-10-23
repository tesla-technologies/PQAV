// SPDX-License-Identifier: MIT OR Apache-2.0
use clap::Parser;
use ml_dsa::{MlDsa44, SigningKey};
use pqav::adts::{hash_audio, split_adts, AdtsError};
use pqav::anchor::{encode, AnchorError, AnchorPayload};
use pqav::cose::{self, CoseError};
use pqav::h264::{hash_video, H264Error};
use pqav::keys::{leer_seed, KeyError};
use pqav::ts::{
    anchor_pes, packetize, parse_packet, parse_pat, parse_pes, parse_pmt, PesAssembler, RawPes,
    SectionAssembler, TsError, NULL_PID, TS,
};
use pqav::units::{
    component_map, find_anchor_pid, map_tuples, Component, Interval, Unit, UnitsError,
};
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
struct StatCalc<T> {
    mean: f64,
    min: T,
    max: T,
}
#[derive(serde::Serialize)]
struct StatCalcF {
    mean: f64,
    min: usize,
    max: usize,
}
#[derive(serde::Serialize)]
struct PercentilesF {
    p50: f64,
    p99: f64,
}
#[derive(serde::Serialize)]
struct PercentilesU {
    p50: u64,
    p99: u64,
    samples: u64,
}

fn calc_stat(v: &[usize]) -> StatCalc<usize> {
    if v.is_empty() {
        return StatCalc {
            mean: 0.0,
            min: 0,
            max: 0,
        };
    }
    let min = *v.iter().min().unwrap();
    let max = *v.iter().max().unwrap();
    let mean = v.iter().sum::<usize>() as f64 / v.len() as f64;
    StatCalc {
        mean: (mean * 100.0).round() / 100.0,
        min,
        max,
    }
}
fn calc_stat_f(v: &[usize]) -> StatCalcF {
    if v.is_empty() {
        return StatCalcF {
            mean: 0.0,
            min: 0,
            max: 0,
        };
    }
    let min = *v.iter().min().unwrap();
    let max = *v.iter().max().unwrap();
    let mean = v.iter().sum::<usize>() as f64 / v.len() as f64;
    StatCalcF {
        mean: (mean * 100.0).round() / 100.0,
        min,
        max,
    }
}
fn calc_perc_f(mut v: Vec<f64>) -> PercentilesF {
    if v.is_empty() {
        return PercentilesF { p50: 0.0, p99: 0.0 };
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len() as f64;
    let i50 = (0.50 * n).ceil() as usize - 1;
    let i99 = (0.99 * n).ceil() as usize - 1;
    PercentilesF {
        p50: (v[i50] * 10.0).round() / 10.0,
        p99: (v[i99] * 10.0).round() / 10.0,
    }
}
fn calc_perc_u(mut v: Vec<u64>) -> PercentilesU {
    let s = v.len() as u64;
    if v.is_empty() {
        return PercentilesU {
            p50: 0,
            p99: 0,
            samples: s,
        };
    }
    v.sort_unstable();
    let n = v.len() as f64;
    let i50 = (0.50 * n).ceil() as usize - 1;
    let i99 = (0.99 * n).ceil() as usize - 1;
    PercentilesU {
        p50: v[i50],
        p99: v[i99],
        samples: s,
    }
}

struct Firmante {
    sk: SigningKey<MlDsa44>,
    kid: [u8; 8],
    stream_id: [u8; 16],
    counter: u64,
    prev: [u8; 32],
    cc: u8,
    anchor_pid: u16,
    mapa: Vec<Component>,
    video_pid: u16,
    audio_pid: Option<u16>,
    video_idx: u8,
    audio_idx: Option<u8>,
    abierto: Interval,
    vistas: HashSet<(u8, u64)>,
    cola: VecDeque<VecDeque<[u8; 188]>>,
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
    fn procesar_pes(&mut self, pid: u16, raw: RawPes, pos: u64) -> Result<(), SignError> {
        let is_video = pid == self.video_pid;
        let p_name = if is_video { "video" } else { "audio" };
        let pes = parse_pes(&raw).map_err(|e| SignError::Ts(e, raw.first_packet))?;
        let pts = pes.pts.ok_or(SignError::SinPts(p_name, raw.first_packet))?;

        let mut unidades = Vec::new();

        if is_video {
            let hash = hash_video(&pes.payload).map_err(|e| SignError::H264(e, pos))?;
            unidades.push(Unit {
                comp: self.video_idx,
                pts,
                hash,
            });
        } else {
            let a_idx = self.audio_idx.unwrap();
            let tramas = split_adts(&pes.payload).map_err(|e| SignError::Adts(e, pos))?;
            for (k, t) in tramas.iter().enumerate() {
                let u_pts = (pts + 1920 * k as u64) % (1 << 33);
                let hash = hash_audio(t);
                unidades.push(Unit {
                    comp: a_idx,
                    pts: u_pts,
                    hash,
                });
            }
        }

        for u in unidades {
            if self.vistas.contains(&(u.comp, u.pts)) {
                return Err(SignError::Repetida {
                    comp: u.comp,
                    pts: u.pts,
                });
            }
            if u.comp == self.video_idx && self.abierto.video_count(self.video_idx) == 6 {
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
        let base = self
            .abierto
            .base()
            .map_err(|e| SignError::Units(e, pos_entrada))?;
        let mut units = Vec::new();
        for u in &self.abierto.units {
            let r = self
                .abierto
                .rel(base, u)
                .map_err(|e| SignError::Units(e, pos_entrada))?;
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
    let args = Args::parse();
    if let Err(e) = run(args) {
        eprintln!("pqav-sign: error: {}", e);
        std::process::ExitCode::from(2)
    } else {
        std::process::ExitCode::SUCCESS
    }
}

fn run(args: Args) -> Result<(), SignError> {
    let datos = std::fs::read(&args.input)
        .map_err(|e| SignError::Leer(args.input.display().to_string(), e))?;
    if datos.len() % TS != 0 {
        return Err(SignError::NoMultiplo);
    }
    let (sk, kid) = leer_seed(&args.key)?;
    let mut stream_id = [0u8; 16];
    getrandom::fill(&mut stream_id).map_err(|_| KeyError::Aleatorio)?;
    let mut f = Firmante {
        sk,
        kid,
        stream_id,
        counter: 0,
        prev: [0; 32],
        cc: 0,
        anchor_pid: args.anchor_pid,
        mapa: Vec::new(),
        video_pid: 0,
        audio_pid: None,
        video_idx: 0,
        audio_idx: None,
        abierto: Interval::default(),
        vistas: HashSet::new(),
        cola: VecDeque::new(),
        pos_entradas: VecDeque::new(),
        payload_sizes: Vec::new(),
        sign_us: Vec::new(),
        video_units_count: 0,
        audio_units_count: 0,
        cose_sizes: Vec::new(),
        pkt_counts: Vec::new(),
        insert_delays: Vec::new(),
        null_packets_used: 0,
        appended_packets: 0,
        bitrate: args.bitrate,
    };
    let mut out_buffer = Vec::with_capacity(datos.len() + 188 * 30);
    let mut pat_asm = SectionAssembler::new();
    let mut pmt_asm = SectionAssembler::new();
    let mut pmt_pid = None;
    let mut v_asm = PesAssembler::new();
    let mut a_asm = PesAssembler::new();
    let mut nulos_in = 0;
    let num_pkts = (datos.len() / TS) as u64;

    for (i, p) in datos.chunks_exact(TS).enumerate() {
        let i = i as u64;
        let pkt = parse_packet(p).map_err(|e| SignError::Ts(e, i))?;

        if pkt.pid == f.anchor_pid {
            return Err(SignError::YaFirmado);
        }

        if pkt.pid == NULL_PID {
            nulos_in += 1;
        }

        let mut replaced = false;
        if pkt.pid == NULL_PID && !f.cola.is_empty() {
            let ancla = f.cola.front_mut().unwrap();
            let p_out = ancla.pop_front().unwrap();
            out_buffer.extend_from_slice(&p_out);
            f.null_packets_used += 1;
            replaced = true;
            if ancla.is_empty() {
                f.cola.pop_front();
                let p_in = f.pos_entradas.pop_front().unwrap();
                let out_idx = (out_buffer.len() / TS - 1) as f64;
                let delay = (out_idx - p_in as f64) * 188.0 * 8.0 / args.bitrate as f64 * 1000.0;
                f.insert_delays.push(delay);
            }
        }

        if !replaced {
            out_buffer.extend_from_slice(p);
        }

        if pkt.pid == 0x0000 {
            if let Some(s) = pat_asm.push(&pkt) {
                pmt_pid = Some(parse_pat(&s).map_err(|e| SignError::Tabla(e, 0x0000, i))?);
            }
        } else if Some(pkt.pid) == pmt_pid {
            if let Some(s) = pmt_asm.push(&pkt) {
                let pmt = parse_pmt(&s).map_err(|e| SignError::Tabla(e, pmt_pid.unwrap(), i))?;
                if f.mapa.is_empty() {
                    if find_anchor_pid(&pmt).is_some()
                        || pmt.es.iter().any(|e| e.pid == f.anchor_pid)
                    {
                        return Err(SignError::YaFirmado);
                    }
                    let m = component_map(&pmt, Some(f.anchor_pid))
                        .map_err(|e| SignError::Units(e, i))?;
                    f.mapa = m;
                    f.video_idx = f.mapa.iter().position(|c| c.stream_type == 0x1B).unwrap() as u8;
                    f.video_pid = f.mapa[f.video_idx as usize].pid;

                    if let Some(pos) = f.mapa.iter().position(|c| c.stream_type == 0x0F) {
                        f.audio_idx = Some(pos as u8);
                        f.audio_pid = Some(f.mapa[pos].pid);
                    }
                } else {
                    let m = component_map(&pmt, Some(f.anchor_pid)).unwrap_or_default();
                    if m != f.mapa || f.mapa[0].pid != f.video_pid {
                        return Err(SignError::PmtCambia(i));
                    }
                }
            }
        } else if !f.mapa.is_empty() {
            if pkt.pid == f.video_pid {
                if let Some(raw) = v_asm.push(&pkt, i) {
                    f.procesar_pes(f.video_pid, raw, i)?;
                }
            } else if Some(pkt.pid) == f.audio_pid {
                if let Some(raw) = a_asm.push(&pkt, i) {
                    f.procesar_pes(f.audio_pid.unwrap(), raw, i)?;
                }
            }
        }
    }

    if f.mapa.is_empty() {
        return Err(SignError::SinTablas);
    }

    if let Some(raw) = v_asm.finish() {
        f.procesar_pes(f.video_pid, raw, num_pkts)?;
    }

    if let Some(a_pid) = f.audio_pid {
        if let Some(raw) = a_asm.finish() {
            f.procesar_pes(a_pid, raw, num_pkts)?;
        }
    }

    if f.counter == 0 && f.abierto.video_count(0) == 0 {
        return Err(SignError::SinUnidades);
    }

    f.cerrar_intervalo(true, num_pkts)?;

    while let Some(mut ancla) = f.cola.pop_front() {
        let p_in = f.pos_entradas.pop_front().unwrap();
        while let Some(pkt) = ancla.pop_front() {
            out_buffer.extend_from_slice(&pkt);
            f.appended_packets += 1;
        }
        let out_idx = (out_buffer.len() / TS - 1) as f64;
        let delay = (out_idx - p_in as f64) * 188.0 * 8.0 / args.bitrate as f64 * 1000.0;
        f.insert_delays.push(delay);
    }

    std::fs::write(&args.out, &out_buffer)
        .map_err(|e| SignError::Escribir(args.out.display().to_string(), e))?;

    let anclas = f.counter;

    if let Some(s) = args.stats {
        let st = Stats {
            anchors: anclas,
            video_units: f.video_units_count,
            audio_units: f.audio_units_count,
            payload_bytes: calc_stat(&f.payload_sizes),
            cose_bytes: calc_stat(&f.cose_sizes),
            ts_packets_per_anchor: calc_stat_f(&f.pkt_counts),
            appended_packets: f.appended_packets,
            insert_delay_ms: calc_perc_f(f.insert_delays),
            sign_us: calc_perc_u(f.sign_us),
            input_packets: num_pkts,
            null_packets_in: nulos_in,
            null_packets_used: f.null_packets_used,
            bitrate_bps: args.bitrate,
        };
        let js = serde_json::to_string_pretty(&st).unwrap();
        std::fs::write(&s, js).map_err(|e| SignError::Escribir(s.display().to_string(), e))?;
    }
    println!(
        "pqav-sign: {} anclas; {} unidades de vídeo y {} de audio; {} paquetes leídos; {} nulos sustituidos; {} añadidos al final",
        anclas, f.video_units_count, f.audio_units_count, num_pkts, f.null_packets_used, f.appended_packets
    );
    Ok(())
}
