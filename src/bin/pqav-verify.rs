// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use clap::Parser;
use pqav::ts::{
    parse_packet, parse_pat, parse_pes, parse_pmt, PesAssembler, RawPes, SectionAssembler, TsError,
    TS,
};
use pqav::units::{component_map, extraer_unidades, find_anchor_pid, map_tuples, Component, Unit};
use std::collections::HashSet;
use std::path::PathBuf;

fn parse_pid(s: &str) -> Result<u16, String> {
    let p = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u16::from_str_radix(h, 16).map_err(|_| "PID inválido")?,
        None => s.parse::<u16>().map_err(|_| "PID inválido")?,
    };
    if !(0x0010..=0x1FFE).contains(&p) {
        return Err(format!("PID 0x{:04X} fuera de rango", p));
    }
    Ok(p)
}

#[derive(clap::Parser, Debug)]
#[command(version, about = "Verifica un TS firmado (primera pasada)")]
struct Args {
    #[arg(long = "pub", value_name = "FICHERO")]
    pub_key: PathBuf,
    #[arg(long = "in", value_name = "FICHERO")]
    input: PathBuf,
    #[arg(long, value_name = "PID", default_value = "0x1FF0", value_parser = parse_pid)]
    anchor_pid: u16,
    #[arg(long)]
    no_expect_signed: bool,
    #[arg(long, value_name = "FICHERO")]
    json: Option<PathBuf>,
    #[arg(long)]
    quiet: bool,
}

#[derive(Debug, thiserror::Error)]
enum VerifyError {
    #[error("{0}")]
    Clave(#[from] pqav::keys::KeyError),
    #[error("no se puede leer {0}: {1}")]
    Leer(String, std::io::Error),
    #[error("el fichero no mide un múltiplo de 188 bytes")]
    NoMultiplo,
    #[error("paquete sin sincronía (paquete {0})")]
    SinSincronia(u64),
    #[error("no se ha encontrado la PAT o la PMT")]
    SinTablas,
    #[error("el MVP solo admite un programa")]
    VariosProgramas,
    #[error("{0}")]
    Mapa(#[from] pqav::units::UnitsError),
}

struct AnclaRecibida {
    cose: Option<Vec<u8>>,
    base: Option<u64>,
}

struct Recogido {
    mapa: Vec<Component>,
    mapas_pmt: Vec<Vec<(u8, String, u8)>>,
    unidades: Vec<Unit>,
    anclas: Vec<AnclaRecibida>,
    pid_anclas: Option<u16>,
    unreadable_pes: usize,
    // received: Received   //se añadirá cuando se complete report
}

fn primera_pasada(datos: &[u8], arg_anchor_pid: u16) -> Result<Recogido, VerifyError> {
    if datos.len() % TS != 0 {
        return Err(VerifyError::NoMultiplo);
    }

    let mut pat_asm = SectionAssembler::new();
    let mut pmt_asm = SectionAssembler::new();
    let mut v_asm = PesAssembler::new();
    let mut a_asm = PesAssembler::new();
    let mut anc_asm = PesAssembler::new();

    let mut pmt_pid = None;
    let mut pmt_bytes_vistas = HashSet::new();
    let mut mapas_pmt = Vec::new();
    let mut mapa_principal = None;

    let mut pid_anclas = None;
    let mut video_pid = None;
    let mut audio_pid = None;
    let mut video_idx = 0;
    let mut audio_idx = 0;

    let mut unidades = Vec::new();
    let mut anclas = Vec::new();
    let mut unreadable_pes = 0;

    for (i, p) in datos.chunks_exact(TS).enumerate() {
        let i = i as u64;
        if p[0] != 0x47 {
            return Err(VerifyError::SinSincronia(i));
        }

        let pkt = match parse_packet(p) {
            Ok(pkt) => pkt,
            Err(TsError::ErrorTransporte) | Err(TsError::CampoAdaptacion) => continue,
            Err(_) => continue,
        };

        if pkt.pid == 0x0000 {
            if let Some(s) = pat_asm.push(&pkt) {
                match parse_pat(&s) {
                    Ok(pid) => pmt_pid = Some(pid),
                    Err(TsError::VariosProgramas) => return Err(VerifyError::VariosProgramas),
                    _ => {}
                }
            }
        } else if Some(pkt.pid) == pmt_pid {
            if let Some(s) = pmt_asm.push(&pkt) {
                if pmt_bytes_vistas.insert(s.clone()) {
                    if let Ok(pmt) = parse_pmt(&s) {
                        let curr_anchor_pid = find_anchor_pid(&pmt).unwrap_or(arg_anchor_pid);
                        let map = component_map(&pmt, Some(curr_anchor_pid))?;
                        mapas_pmt.push(map_tuples(&map));

                        if mapa_principal.is_none() {
                            pid_anclas = Some(curr_anchor_pid);
                            if let Some(pos) = map.iter().position(|c| c.stream_type == 0x1B) {
                                video_pid = Some(map[pos].pid);
                                video_idx = pos as u8;
                            }
                            if let Some(pos) = map.iter().position(|c| c.stream_type == 0x0F) {
                                audio_pid = Some(map[pos].pid);
                                audio_idx = pos as u8;
                            }
                            mapa_principal = Some(map);
                        }
                    }
                }
            }
        } else if Some(pkt.pid) == video_pid {
            if let Some(raw) = v_asm.push(&pkt, i) {
                match parse_pes(&raw) {
                    Ok(pes) => match extraer_unidades(&pes, true, video_idx) {
                        Ok(uns) => unidades.extend(uns),
                        Err(_) => unreadable_pes += 1,
                    },
                    Err(_) => unreadable_pes += 1,
                }
            }
        } else if Some(pkt.pid) == audio_pid {
            if let Some(raw) = a_asm.push(&pkt, i) {
                match parse_pes(&raw) {
                    Ok(pes) => match extraer_unidades(&pes, false, audio_idx) {
                        Ok(uns) => unidades.extend(uns),
                        Err(_) => unreadable_pes += 1,
                    },
                    Err(_) => unreadable_pes += 1,
                }
            }
        } else if Some(pkt.pid) == pid_anclas && mapa_principal.is_some() {
            if let Some(raw) = anc_asm.push(&pkt, i) {
                match parse_pes(&raw) {
                    Ok(pes) => {
                        if pes.pts.is_some() {
                            anclas.push(AnclaRecibida {
                                cose: Some(pes.payload),
                                base: pes.pts,
                            });
                        } else {
                            anclas.push(AnclaRecibida {
                                cose: None,
                                base: None,
                            });
                        }
                    }
                    Err(_) => anclas.push(AnclaRecibida {
                        cose: None,
                        base: None,
                    }),
                }
            }
        }
    }

    if mapa_principal.is_none() {
        return Err(VerifyError::SinTablas);
    }

    let mut finish_av = |raw: Option<RawPes>, is_video, idx| {
        if let Some(r) = raw {
            match parse_pes(&r) {
                Ok(pes) => match extraer_unidades(&pes, is_video, idx) {
                    Ok(uns) => unidades.extend(uns),
                    Err(_) => unreadable_pes += 1,
                },
                Err(_) => unreadable_pes += 1,
            }
        }
    };
    finish_av(v_asm.finish(), true, video_idx);
    finish_av(a_asm.finish(), false, audio_idx);

    if let Some(raw) = anc_asm.finish() {
        match parse_pes(&raw) {
            Ok(pes) => {
                if pes.pts.is_some() {
                    anclas.push(AnclaRecibida {
                        cose: Some(pes.payload),
                        base: pes.pts,
                    });
                } else {
                    anclas.push(AnclaRecibida {
                        cose: None,
                        base: None,
                    });
                }
            }
            Err(_) => anclas.push(AnclaRecibida {
                cose: None,
                base: None,
            }),
        }
    }

    Ok(Recogido {
        mapa: mapa_principal.unwrap(),
        mapas_pmt,
        unidades,
        anclas,
        pid_anclas,
        unreadable_pes,
    })
}

fn main() {
    let args = Args::parse();

    let datos = match std::fs::read(&args.input) {
        Ok(d) => d,
        Err(e) => {
            let err = VerifyError::Leer(args.input.display().to_string(), e);
            eprintln!("pqav-verify: error: {}", err);
            std::process::exit(2);
        }
    };

    match primera_pasada(&datos, args.anchor_pid) {
        Ok(r) => {
            let _ = r.mapa.len();
            if let Some(primera_ancla) = r.anclas.first() {
                let _ = primera_ancla.cose.as_ref();
                let _ = primera_ancla.base;
            }

            let video_count = r.unidades.iter().filter(|u| u.comp == 0).count();
            let audio_count = r.unidades.len() - video_count;
            eprintln!(
                "anclas={} video={} audio={} ilegibles={} pmts={} pid_anclas={:?}",
                r.anclas.len(),
                video_count,
                audio_count,
                r.unreadable_pes,
                r.mapas_pmt.len(),
                r.pid_anclas
            );
        }
        Err(e) => {
            eprintln!("pqav-verify: error: {}", e);
            std::process::exit(2);
        }
    }
}
