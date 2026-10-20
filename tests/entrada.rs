// SPDX-License-Identifier: MIT OR Apache-2.0
use pqav::ts::{
    parse_packet, parse_pat, parse_pes, parse_pmt, pts_dif, Pes, PesAssembler, Pmt,
    SectionAssembler, PAT_PID, TS,
};
use std::collections::BTreeMap;

fn parse_entrada_ts(datos: &[u8]) -> (Pmt, Vec<(u16, Pes)>) {
    let mut pat_asm = SectionAssembler::new();
    let mut pmt_asm = SectionAssembler::new();
    let mut pmt_pid = None;
    let mut pmt_valida = None;

    for p in datos.chunks_exact(TS) {
        let pkt = parse_packet(p).unwrap();
        if pkt.pid == PAT_PID {
            if let Some(s) = pat_asm.push(&pkt) {
                pmt_pid = Some(parse_pat(&s).unwrap());
            }
        } else if Some(pkt.pid) == pmt_pid {
            if let Some(s) = pmt_asm.push(&pkt) {
                pmt_valida = Some(parse_pmt(&s).unwrap());
                break;
            }
        }
    }

    let pmt = pmt_valida.expect("no se encontró PMT válida en los datos");

    let mut video_pid = None;
    let mut audio_pid = None;
    for es in &pmt.es {
        if es.stream_type == 0x1B || es.stream_type == 0x02 {
            video_pid = Some(es.pid);
        } else if es.stream_type == 0x0F || es.stream_type == 0x03 || es.stream_type == 0x04 {
            audio_pid = Some(es.pid);
        }
    }

    let video_pid = video_pid.expect("no hay stream de vídeo en la PMT");

    let mut video_asm = PesAssembler::new();
    let mut audio_asm = PesAssembler::new();
    let mut pes_list = Vec::new();

    for (index, p) in datos.chunks_exact(TS).enumerate() {
        let pkt = parse_packet(p).unwrap();
        let idx = index as u64;

        if pkt.pid == video_pid {
            if let Some(raw) = video_asm.push(&pkt, idx) {
                pes_list.push((video_pid, parse_pes(&raw).unwrap()));
            }
        } else if Some(pkt.pid) == audio_pid {
            let a_pid = audio_pid.unwrap();
            if let Some(raw) = audio_asm.push(&pkt, idx) {
                pes_list.push((a_pid, parse_pes(&raw).unwrap()));
            }
        }
    }

    if let Some(raw) = video_asm.finish() {
        pes_list.push((video_pid, parse_pes(&raw).unwrap()));
    }
    if let Some(a_pid) = audio_pid {
        if let Some(raw) = audio_asm.finish() {
            pes_list.push((a_pid, parse_pes(&raw).unwrap()));
        }
    }

    (pmt, pes_list)
}

#[test]
#[ignore = "necesita testdata/entrada.ts"]
fn m1_tablas_de_entrada() {
    let datos = std::fs::read("testdata/entrada.ts").expect("falta testdata/entrada.ts");
    assert_eq!(datos.len() % TS, 0);
    let mut por_pid: BTreeMap<u16, u64> = BTreeMap::new();
    let mut pat = SectionAssembler::new();
    let mut pmt = SectionAssembler::new();
    let mut pmt_pid = None;
    let mut impresa = false;
    for p in datos.chunks_exact(TS) {
        let pkt = parse_packet(p).unwrap();
        *por_pid.entry(pkt.pid).or_default() += 1;
        if pkt.pid == PAT_PID {
            if let Some(s) = pat.push(&pkt) {
                pmt_pid = Some(parse_pat(&s).unwrap());
            }
        } else if Some(pkt.pid) == pmt_pid && !impresa {
            if let Some(s) = pmt.push(&pkt) {
                println!("{:?}", parse_pmt(&s).unwrap());
                impresa = true;
            }
        }
    }
    for (pid, n) in &por_pid {
        println!("0x{pid:04X} {n}");
    }
}

#[test]
#[ignore = "necesita testdata/entrada.ts"]
fn m2_cuenta_pes_de_entrada() {
    let datos = std::fs::read("testdata/entrada.ts").expect("falta testdata/entrada.ts");
    assert_eq!(datos.len() % TS, 0);

    let (pmt, pes_list) = parse_entrada_ts(&datos);
    let video_pid = pmt.es.iter().find(|es| es.stream_type == 0x1B).unwrap().pid;
    let audio_pid = pmt
        .es
        .iter()
        .find(|es| es.stream_type == 0x0F)
        .map(|es| es.pid);

    let mut v_count = 0;
    let mut v_sin_pts = 0;
    let mut a_count = 0;
    let mut a_sin_pts = 0;
    let mut video_pts_list = Vec::new();

    for (pid, pes) in pes_list {
        if pid == video_pid {
            v_count += 1;
            if let Some(pts) = pes.pts {
                video_pts_list.push(pts);
            } else {
                v_sin_pts += 1;
            }
        } else if Some(pid) == audio_pid {
            a_count += 1;
            if pes.pts.is_none() {
                a_sin_pts += 1;
            }
        }
    }

    println!("vídeo: {v_count} PES, {v_sin_pts} sin PTS");
    println!("audio: {a_count} PES, {a_sin_pts} sin PTS");

    // mostrar 10 primeros PTS de vídeo y sus diferencias
    println!("10 primeros PTS de vídeo:");
    for i in 0..std::cmp::min(10, video_pts_list.len()) {
        if i == 0 {
            println!("PTS[0]: {}", video_pts_list[0]);
        } else {
            let dif = pts_dif(video_pts_list[i], video_pts_list[i - 1]);
            println!("PTS[{}]: {} (dif: {})", i, video_pts_list[i], dif);
        }
    }

    assert_eq!(v_count, 1500);
    assert_eq!(v_sin_pts, 0);
}

#[test]
#[ignore = "necesita testdata/entrada.ts"]
fn m3_unidades_de_entrada() {
    use pqav::adts::split_adts;
    use pqav::h264::hash_video;
    use std::collections::BTreeMap;

    let datos = std::fs::read("testdata/entrada.ts").expect("falta testdata/entrada.ts");
    let (pmt, pes_list) = parse_entrada_ts(&datos);
    let video_pid = pmt.es.iter().find(|es| es.stream_type == 0x1B).unwrap().pid;
    let audio_pid = pmt
        .es
        .iter()
        .find(|es| es.stream_type == 0x0F)
        .map(|es| es.pid);

    let mut video_units = 0;
    let mut audio_units = 0;
    let mut errores = 0;
    let mut histograma: BTreeMap<usize, usize> = BTreeMap::new();

    for (pid, pes) in pes_list {
        if pid == video_pid {
            match hash_video(&pes.payload) {
                Ok(_) => video_units += 1,
                Err(_) => errores += 1,
            }
        } else if Some(pid) == audio_pid {
            match split_adts(&pes.payload) {
                Ok(tramas) => {
                    *histograma.entry(tramas.len()).or_default() += 1;
                    audio_units += tramas.len();
                }
                Err(_) => errores += 1,
            }
        }
    }

    println!("Vídeo: {video_units} unidades");
    println!("Audio: {audio_units} unidades");
    println!("Errores: {errores}");
    println!("Histograma tramas por PES audio: {:?}", histograma);

    assert_eq!(video_units, 1500);
    assert_eq!(errores, 0);
}

#[test]
#[ignore = "necesita testdata/entrada.ts"]
fn m4_intervalos_de_entrada() {
    use pqav::anchor::{encode, AnchorPayload};
    use pqav::units::{component_map, map_tuples, parse_pes_to_intervals};

    let datos = std::fs::read("testdata/entrada.ts").expect("falta testdata/entrada.ts");
    let (pmt, pes_list) = parse_entrada_ts(&datos);

    let comps = component_map(&pmt, None).unwrap();
    let comp_tuples = map_tuples(&comps);

    let video_pid = comps[0].pid;
    let audio_pid = comps.get(1).map(|c| c.pid);

    // Usar la función de la librería en lugar del bucle local
    let intervalos = parse_pes_to_intervals(&pes_list, video_pid, audio_pid).unwrap();

    assert_eq!(intervalos.len(), 250);

    let mut total_audio_tramas = 0;
    let mut total_bytes_carga = 0;

    for (counter, iv) in intervalos.iter().enumerate() {
        assert_eq!(iv.video_count(0), 6);

        let base = iv.base().unwrap();
        let mut units_encoded = Vec::new();
        for u in &iv.units {
            let rel = iv.rel(base, u).unwrap();
            units_encoded.push((u.comp, rel, u.hash));
            if u.comp == 1 {
                total_audio_tramas += 1;
            }
        }

        let is_final = counter == intervalos.len() - 1;
        let payload = AnchorPayload {
            stream_id: [0u8; 16],
            counter: counter as u64,
            prev: [0u8; 32],
            components: comp_tuples.clone(),
            units: units_encoded,
            is_final,
        };

        let carga = encode(&payload).unwrap();
        total_bytes_carga += carga.len();

        if counter == 0 {
            println!(
                "Primeros 40 bytes de la primera carga: {:02X?}",
                &carga[..40]
            );
        }
    }

    let media_audio = total_audio_tramas as f64 / intervalos.len() as f64;
    let media_bytes = total_bytes_carga as f64 / intervalos.len() as f64;

    println!("Número de intervalos: {}", intervalos.len());
    println!("Media de tramas de audio por intervalo: {:.2}", media_audio);
    println!("Media de bytes de carga CBOR: {:.2}", media_bytes);
}
