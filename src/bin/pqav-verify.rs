// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use clap::Parser;
use ml_dsa::{EncodedVerifyingKey, MlDsa44, VerifyingKey};
use pqav::anchor::decode_strict;
use pqav::cose::{self, CoseError};
use pqav::keys::kid_of;
use pqav::report::{
    percentile, Global, IntervalReport, Percentiles, Received, Report, UnitRef, Verdict,
};
use pqav::ts::{
    parse_packet, parse_pat, parse_pes, parse_pmt, PesAssembler, RawPes, SectionAssembler, TsError,
    PTS_MOD, TS,
};
use pqav::units::{component_map, extraer_unidades, find_anchor_pid, map_tuples, Component, Unit};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

#[derive(clap::Parser, Debug)]
#[command(version, about = "Verifica un TS firmado (primera pasada)")]
struct Args {
    #[arg(long = "pub", value_name = "FICHERO")]
    pub_key: PathBuf,
    #[arg(long = "in", value_name = "FICHERO")]
    input: PathBuf,
    #[arg(long, value_name = "PID", default_value = "0x1FF0", value_parser = pqav::ts::parse_pid)]
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

    let mapa = mapa_principal.ok_or(VerifyError::SinTablas)?;

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
        mapa,
        mapas_pmt,
        unidades,
        anclas,
        unreadable_pes,
    })
}

fn comprobar_cadena_anclas(
    p: &pqav::anchor::AnchorPayload,
    stream_id_0: &mut Option<[u8; 16]>,
    ultimo_valido: &Option<(u64, [u8; 32])>,
    invalidas_desde_ultimo: u64,
    gap_before: &mut u64,
) -> (Vec<Verdict>, Option<String>) {
    let mut veredictos = vec![Verdict::Autentico];
    let mut detail = None;

    if stream_id_0.is_none() {
        *stream_id_0 = Some(p.stream_id);
    }
    if Some(p.stream_id) != *stream_id_0 {
        veredictos.push(Verdict::Empalme);
        if detail.is_none() {
            detail = Some("stream_id distinto".to_string());
        }
    }

    let esperado = ultimo_valido.map_or(invalidas_desde_ultimo, |(last_c, _)| {
        last_c + 1 + invalidas_desde_ultimo
    });

    if p.counter > esperado {
        *gap_before = p.counter - esperado;
    } else if p.counter < esperado {
        veredictos.push(Verdict::Empalme);
        if detail.is_none() {
            detail = Some("contador hacia atrás".to_string());
        }
    } else if invalidas_desde_ultimo == 0 {
        if let Some((_, last_hash)) = ultimo_valido {
            if p.prev != *last_hash {
                veredictos.push(Verdict::Empalme);
                if detail.is_none() {
                    detail = Some("prev no coincide".to_string());
                }
            }
        }
    }
    (veredictos, detail)
}

fn comparar_unidades(
    p: &pqav::anchor::AnchorPayload,
    r: &Recogido,
    base: u64,
    indice: &HashMap<(u8, u64), usize>,
    cubiertas: &mut [bool],
    veredictos: &mut Vec<Verdict>,
) -> (usize, usize, usize, usize, Vec<UnitRef>, Vec<UnitRef>) {
    let mut video_ok = 0;
    let mut video_total = 0;
    let mut audio_ok = 0;
    let mut audio_total = 0;
    let mut modified = Vec::new();
    let mut missing = Vec::new();

    for &(comp, rel, hash) in &p.units {
        let is_video = r
            .mapa
            .get(comp as usize)
            .is_some_and(|c| c.stream_type == 0x1B);
        if is_video {
            video_total += 1;
        } else {
            audio_total += 1;
        }

        let pts = (base + rel as u64) % PTS_MOD;
        if let Some(&idx) = indice.get(&(comp, pts)) {
            cubiertas[idx] = true;
            if r.unidades[idx].hash != hash {
                modified.push(UnitRef { comp, pts });
            } else if is_video {
                video_ok += 1;
            } else {
                audio_ok += 1;
            }
        } else {
            missing.push(UnitRef { comp, pts });
        }
    }

    if !modified.is_empty() {
        veredictos.push(Verdict::Manipulado);
    } else if !missing.is_empty() {
        veredictos.push(Verdict::Incompleto);
    }

    (
        video_ok,
        video_total,
        audio_ok,
        audio_total,
        modified,
        missing,
    )
}

fn montar_informe(
    r: &Recogido,
    intervals: Vec<IntervalReport>,
    cubiertas: &[bool],
    verify_times: &mut [u64],
    hueco: bool,
    final_presente: bool,
) -> Report {
    let unsigned_units = cubiertas.iter().filter(|&&c| !c).count();
    let mut reasons = Vec::new();

    for &v in &[
        Verdict::FirmaInvalida,
        Verdict::Empalme,
        Verdict::MapaAlterado,
        Verdict::Manipulado,
        Verdict::Incompleto,
    ] {
        if intervals.iter().any(|i| i.verdict == v) {
            reasons.push(
                match v {
                    Verdict::FirmaInvalida => "FIRMA_INVALIDA",
                    Verdict::Empalme => "EMPALME",
                    Verdict::MapaAlterado => "MAPA_ALTERADO",
                    Verdict::Manipulado => "MANIPULADO",
                    Verdict::Incompleto => "INCOMPLETO",
                    _ => unreachable!(),
                }
                .to_string(),
            );
        }
    }
    if hueco {
        reasons.push("HUECO".to_string());
    }
    if unsigned_units > 0 {
        reasons.push("NO_FIRMADA".to_string());
    }
    if !final_presente {
        reasons.push("SIN_FINAL".to_string());
    }

    let global = if r.anclas.is_empty() {
        reasons.clear();
        Global::SinFirmar
    } else if reasons.is_empty() {
        Global::Autentico
    } else {
        Global::Rechazado
    };

    let verify_us = if !verify_times.is_empty() {
        verify_times.sort_unstable();
        Some(Percentiles {
            p50: percentile(verify_times, 50).unwrap_or(0),
            p99: percentile(verify_times, 99).unwrap_or(0),
        })
    } else {
        None
    };

    Report {
        global,
        reasons,
        error: None,
        anchors: r.anclas.len(),
        intervals,
        received_units: Received {
            video: r.unidades.iter().filter(|u| u.comp == 0).count(),
            audio: r.unidades.iter().filter(|u| u.comp == 1).count(),
        },
        unsigned_units,
        unreadable_pes: r.unreadable_pes,
        final_anchor: final_presente,
        verify_us,
    }
}

fn intervalo_invalido(index: usize, base: Option<u64>, detail: &str) -> IntervalReport {
    IntervalReport {
        index,
        counter: None,
        base,
        verdict: Verdict::FirmaInvalida,
        detail: Some(detail.to_string()),
        gap_before: 0,
        video_ok: 0,
        video_total: 0,
        audio_ok: 0,
        audio_total: 0,
        modified: vec![],
        missing: vec![],
    }
}

fn segunda_pasada(r: &Recogido, vk: &VerifyingKey<MlDsa44>, kid: &[u8; 8]) -> Report {
    let mut indice = HashMap::new();
    for (i, u) in r.unidades.iter().enumerate() {
        indice.entry((u.comp, u.pts)).or_insert(i);
    }
    let mut cubiertas = vec![false; r.unidades.len()];

    let mut stream_id_0 = None;
    let mut ultimo_valido: Option<(u64, [u8; 32])> = None;
    let mut invalidas_desde_ultimo = 0;
    let mut hueco = false;
    let mut final_presente = false;

    let mut intervals = Vec::new();
    let mut verify_times = Vec::new();

    for (k, ancla) in r.anclas.iter().enumerate() {
        let mut gap_before = 0;
        let (cose_bytes, base) = match (&ancla.cose, ancla.base) {
            (Some(c), Some(b)) => (c, b),
            _ => {
                intervals.push(intervalo_invalido(k, None, "PES de ancla ilegible"));
                invalidas_desde_ultimo += 1;
                continue;
            }
        };

        let t0 = Instant::now();
        let v_res = cose::verify(vk, kid, cose_bytes);

        let (p, hash_cose) = match v_res {
            Ok(v) => {
                verify_times.push(t0.elapsed().as_micros() as u64);
                match decode_strict(&v.payload) {
                    Ok(p) => (p, v.hash_cose),
                    Err(_) => {
                        intervals.push(intervalo_invalido(k, Some(base), "carga no canónica"));
                        invalidas_desde_ultimo += 1;
                        continue;
                    }
                }
            }
            Err(e) => {
                let det = match e {
                    CoseError::MalFormado(_) => "COSE mal formado",
                    CoseError::KidDesconocido => "kid desconocido",
                    _ => "firma no válida",
                };
                intervals.push(intervalo_invalido(k, Some(base), det));
                invalidas_desde_ultimo += 1;
                continue;
            }
        };

        let (mut veredictos, mut detail) = comprobar_cadena_anclas(
            &p,
            &mut stream_id_0,
            &ultimo_valido,
            invalidas_desde_ultimo,
            &mut gap_before,
        );
        if gap_before > 0 {
            hueco = true;
        }

        if !r.mapas_pmt.contains(&p.components) {
            veredictos.push(Verdict::MapaAlterado);
            if detail.is_none() {
                detail = Some("mapa distinto del de la PMT".to_string());
            }
        }

        let (video_ok, video_total, audio_ok, audio_total, modified, missing) =
            comparar_unidades(&p, r, base, &indice, &mut cubiertas, &mut veredictos);

        let verdict = *veredictos.iter().min().unwrap_or(&Verdict::Autentico);
        let final_detail = if verdict <= Verdict::MapaAlterado {
            detail
        } else {
            None
        };

        ultimo_valido = Some((p.counter, hash_cose));
        invalidas_desde_ultimo = 0;
        if p.is_final {
            final_presente = true;
        }

        intervals.push(IntervalReport {
            index: k,
            counter: Some(p.counter),
            base: Some(base),
            verdict,
            detail: final_detail,
            gap_before,
            video_ok,
            video_total,
            audio_ok,
            audio_total,
            modified,
            missing,
        });
    }

    montar_informe(
        r,
        intervals,
        &cubiertas,
        &mut verify_times,
        hueco,
        final_presente,
    )
}

fn error_report(msg: String) -> Report {
    Report {
        global: Global::ErrorEntrada,
        reasons: vec![],
        error: Some(msg),
        anchors: 0,
        intervals: vec![],
        received_units: Received { video: 0, audio: 0 },
        unsigned_units: 0,
        unreadable_pes: 0,
        final_anchor: false,
        verify_us: None,
    }
}

fn imprimir_report(r: &Report, quiet: bool, no_expect: bool) {
    if !quiet && r.global != Global::ErrorEntrada && r.global != Global::SinFirmar {
        for i in &r.intervals {
            let base_str = i
                .base
                .map_or("-----------".to_string(), |b| format!("{:011}", b));
            let mut parts = Vec::new();
            if let Some(ref det) = i.detail {
                parts.push(det.clone());
            }
            if i.gap_before > 0 {
                parts.push(format!(
                    "HUECO: faltan {} anclas antes de esta",
                    i.gap_before
                ));
            }

            let v_mod = i
                .modified
                .iter()
                .filter(|u| u.comp == 0)
                .map(|u| u.pts.to_string())
                .collect::<Vec<_>>();
            let a_mod = i
                .modified
                .iter()
                .filter(|u| u.comp == 1)
                .map(|u| u.pts.to_string())
                .collect::<Vec<_>>();
            if !v_mod.is_empty() {
                parts.push(format!(
                    "vídeo: {} modificadas (pts {})",
                    v_mod.len(),
                    v_mod.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
                ));
            }
            if !a_mod.is_empty() {
                parts.push(format!(
                    "audio: {} modificadas (pts {})",
                    a_mod.len(),
                    a_mod.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
                ));
            }

            let v_mis = i
                .missing
                .iter()
                .filter(|u| u.comp == 0)
                .map(|u| u.pts.to_string())
                .collect::<Vec<_>>();
            let a_mis = i
                .missing
                .iter()
                .filter(|u| u.comp == 1)
                .map(|u| u.pts.to_string())
                .collect::<Vec<_>>();
            if !v_mis.is_empty() {
                parts.push(format!(
                    "vídeo: {} faltan (pts {})",
                    v_mis.len(),
                    v_mis.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
                ));
            }
            if !a_mis.is_empty() {
                parts.push(format!(
                    "audio: {} faltan (pts {})",
                    a_mis.len(),
                    a_mis.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
                ));
            }

            let d = if parts.is_empty() {
                String::new()
            } else {
                format!("  {}", parts.join("; "))
            };
            let v_str = match i.verdict {
                Verdict::FirmaInvalida => "FIRMA_INVALIDA",
                Verdict::Empalme => "EMPALME",
                Verdict::MapaAlterado => "MAPA_ALTERADO",
                Verdict::Manipulado => "MANIPULADO",
                Verdict::Incompleto => "INCOMPLETO",
                Verdict::Autentico => "AUTENTICO",
            };
            if i.verdict == Verdict::FirmaInvalida {
                println!("#{:04} base={} {}{}", i.index, base_str, v_str, d);
            } else {
                println!(
                    "#{:04} base={} video {}/{} audio {}/{} {}{}",
                    i.index,
                    base_str,
                    i.video_ok,
                    i.video_total,
                    i.audio_ok,
                    i.audio_total,
                    v_str,
                    d
                );
            }
        }
    }

    if r.global == Global::ErrorEntrada {
        println!(
            "RESULTADO: ERROR_ENTRADA  {}",
            r.error.as_deref().unwrap_or("")
        );
    } else if r.global == Global::SinFirmar {
        if no_expect {
            println!("AVISO: el fichero no lleva firmas y se ha pedido no exigirlas");
        }
        println!("RESULTADO: SIN_FIRMAR  no hay firmas en el fichero");
    } else {
        let auth = r
            .intervals
            .iter()
            .filter(|i| i.verdict == Verdict::Autentico)
            .count();
        let mut stats = format!("intervalos={} autenticos={}", r.intervals.len(), auth);
        let fi = r
            .intervals
            .iter()
            .filter(|i| i.verdict == Verdict::FirmaInvalida)
            .count();
        if fi > 0 {
            stats.push_str(&format!(" firmas_invalidas={}", fi));
        }
        let em = r
            .intervals
            .iter()
            .filter(|i| i.verdict == Verdict::Empalme)
            .count();
        if em > 0 {
            stats.push_str(&format!(" empalmes={}", em));
        }
        let ma = r
            .intervals
            .iter()
            .filter(|i| i.verdict == Verdict::MapaAlterado)
            .count();
        if ma > 0 {
            stats.push_str(&format!(" mapas_alterados={}", ma));
        }
        let mn = r
            .intervals
            .iter()
            .filter(|i| i.verdict == Verdict::Manipulado)
            .count();
        if mn > 0 {
            stats.push_str(&format!(" manipulados={}", mn));
        }
        let inc = r
            .intervals
            .iter()
            .filter(|i| i.verdict == Verdict::Incompleto)
            .count();
        if inc > 0 {
            stats.push_str(&format!(" incompletos={}", inc));
        }
        if r.unsigned_units > 0 {
            stats.push_str(&format!(" no_firmadas={}", r.unsigned_units));
        }

        let mot = if r.reasons.is_empty() {
            "ninguno".to_string()
        } else {
            r.reasons.join(", ")
        };
        let g = if r.global == Global::Autentico {
            "AUTENTICO"
        } else {
            "RECHAZADO"
        };
        println!("RESULTADO: {}  {}  motivos: {}", g, stats, mot);
    }
}

fn salir_con_error(msg: String, args: &Args) -> ExitCode {
    let rep = error_report(msg.clone());
    imprimir_report(&rep, args.quiet, args.no_expect_signed);
    if let Some(p) = &args.json {
        if let Ok(js) = serde_json::to_string_pretty(&rep) {
            let _ = std::fs::write(p, js);
        }
    }
    eprintln!("pqav-verify: error: {}", msg);
    ExitCode::from(2)
}

fn run() -> Result<ExitCode, ()> {
    let args = Args::parse();

    let key_bytes = match std::fs::read(&args.pub_key) {
        Ok(b) => b,
        Err(e) => {
            return Ok(salir_con_error(
                VerifyError::Leer(args.pub_key.display().to_string(), e).to_string(),
                &args,
            ))
        }
    };

    if key_bytes.len() != 1312 {
        let msg = format!(
            "clave pública inválida en {}: mide {} bytes y tiene que medir 1312",
            args.pub_key.display(),
            key_bytes.len()
        );
        return Ok(salir_con_error(msg, &args));
    }

    let enc_vk = EncodedVerifyingKey::<MlDsa44>::try_from(&key_bytes[..]).map_err(|_| ())?;
    let vk = VerifyingKey::<MlDsa44>::decode(&enc_vk);
    let kid = kid_of(&key_bytes);

    let datos = match std::fs::read(&args.input) {
        Ok(d) => d,
        Err(e) => {
            return Ok(salir_con_error(
                VerifyError::Leer(args.input.display().to_string(), e).to_string(),
                &args,
            ))
        }
    };

    let recogido = match primera_pasada(&datos, args.anchor_pid) {
        Ok(r) => r,
        Err(e) => return Ok(salir_con_error(e.to_string(), &args)),
    };

    let report = segunda_pasada(&recogido, &vk, &kid);

    imprimir_report(&report, args.quiet, args.no_expect_signed);

    let mut io_error = false;
    if let Some(json_path) = args.json {
        if let Ok(js) = serde_json::to_string_pretty(&report) {
            if let Err(e) = std::fs::write(&json_path, js) {
                eprintln!(
                    "pqav-verify: error: no se puede escribir {}: {}",
                    json_path.display(),
                    e
                );
                io_error = true;
            }
        }
    }
    if io_error {
        return Ok(ExitCode::from(2));
    }
    match report.global {
        Global::Autentico => Ok(ExitCode::from(0)),
        Global::Rechazado => Ok(ExitCode::from(1)),
        Global::ErrorEntrada => Ok(ExitCode::from(2)),
        Global::SinFirmar => {
            if args.no_expect_signed {
                Ok(ExitCode::from(0))
            } else {
                Ok(ExitCode::from(3))
            }
        }
    }
}

fn main() -> ExitCode {
    run().unwrap_or(ExitCode::from(2))
}
