// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn get_temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("pqav_ataque_{}_{}", std::process::id(), name))
}

fn run_verify(input: &PathBuf, json: Option<&PathBuf>) -> (Option<i32>, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_pqav-verify"));
    cmd.args(["--pub", "testdata/muestra/fuente.pub", "--in"]);
    cmd.arg(input);
    if let Some(j) = json {
        cmd.args(["--json"]);
        cmd.arg(j);
    }
    cmd.arg("--quiet");
    let output = cmd.output().expect("Falló la ejecución de pqav-verify");
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (output.status.code(), stderr)
}

fn check_json_reason(json_path: &PathBuf, expected_reason: &str) {
    let content = fs::read_to_string(json_path).expect("No se generó el JSON");
    assert!(
        content.contains(&format!("\"{}\"", expected_reason)),
        "El JSON no contiene el motivo {}. Contenido: {}",
        expected_reason,
        content
    );
}

#[test]
fn fichero_vacio() {
    let out = get_temp_path("vacio.ts");
    fs::write(&out, b"").unwrap();
    let (code, stderr) = run_verify(&out, None);
    assert_eq!(code, Some(2));
    assert!(!stderr.contains("panicked"));
    let _ = fs::remove_file(out);
}

#[test]
fn tamano_no_multiplo() {
    let out = get_temp_path("no_multiplo.ts");
    let data = vec![0x47; 1885];
    fs::write(&out, &data).unwrap();
    let (code, stderr) = run_verify(&out, None);
    assert_eq!(code, Some(2));
    assert!(!stderr.contains("panicked"));
    let _ = fs::remove_file(out);
}

#[test]
fn basura() {
    let out = get_temp_path("basura.ts");

    let mut data = vec![0u8; 188 * 50];
    let mut seed: u32 = 12345;
    for b in data.iter_mut() {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        *b = (seed >> 16) as u8;
    }
    fs::write(&out, &data).unwrap();
    let (code, stderr) = run_verify(&out, None);
    assert_eq!(code, Some(2));
    assert!(!stderr.contains("panicked"));
    let _ = fs::remove_file(out);
}

#[test]
#[ignore = "necesita testdata/muestra/firmado_10s.ts"]
fn sesion_repetida() {
    let mut data = fs::read("testdata/muestra/firmado_10s.ts").unwrap();
    let clone = data.clone();
    data.extend(clone);
    let out = get_temp_path("repetida.ts");
    let json = get_temp_path("repetida.json");
    fs::write(&out, &data).unwrap();
    let (code, _) = run_verify(&out, Some(&json));
    assert_eq!(code, Some(1));
    check_json_reason(&json, "EMPALME");
    let _ = fs::remove_file(out);
    let _ = fs::remove_file(json);
}

#[test]
#[ignore = "necesita testdata/muestra/firmado_10s.ts"]
fn ancla_duplicada() {
    let data = fs::read("testdata/muestra/firmado_10s.ts").unwrap();
    let mut out_data = Vec::new();
    let mut anchor_packets = Vec::new();
    let mut pusi_count = 0;

    for chunk in data.chunks_exact(188) {
        let pid = (((chunk[1] & 0x1F) as u16) << 8) | (chunk[2] as u16);
        if pid == 0x1FF0 {
            if (chunk[1] & 0x40) != 0 {
                pusi_count += 1;
            }
            if pusi_count == 6 {
                anchor_packets.extend_from_slice(chunk);
            }
        }
    }

    pusi_count = 0;

    for chunk in data.chunks_exact(188) {
        out_data.extend_from_slice(chunk);
        let pid = (((chunk[1] & 0x1F) as u16) << 8) | (chunk[2] as u16);
        if pid == 0x1FF0 && (chunk[1] & 0x40) != 0 {
            pusi_count += 1;
            if pusi_count == 22 {
                out_data.extend_from_slice(&anchor_packets);
            }
        }
    }
    let out = get_temp_path("duplicada.ts");
    let json = get_temp_path("duplicada.json");
    fs::write(&out, &out_data).unwrap();
    let (code, _) = run_verify(&out, Some(&json));
    assert_eq!(code, Some(1));
    check_json_reason(&json, "EMPALME");
    let _ = fs::remove_file(out);
    let _ = fs::remove_file(json);
}

#[test]
#[ignore = "necesita testdata/muestra/firmado_10s.ts"]
fn ancla_eliminada() {
    let data = fs::read("testdata/muestra/firmado_10s.ts").unwrap();
    let mut out_data = Vec::new();
    let mut pusi_count = 0;

    for chunk in data.chunks_exact(188) {
        let pid = (((chunk[1] & 0x1F) as u16) << 8) | (chunk[2] as u16);
        if pid == 0x1FF0 {
            if (chunk[1] & 0x40) != 0 {
                pusi_count += 1;
            }
            if pusi_count == 8 {
                continue;
            }
        }
        out_data.extend_from_slice(chunk);
    }

    let out = get_temp_path("eliminada.ts");
    let json = get_temp_path("eliminada.json");
    fs::write(&out, &out_data).unwrap();
    let (code, _) = run_verify(&out, Some(&json));
    assert_eq!(code, Some(1));
    check_json_reason(&json, "HUECO");
    let _ = fs::remove_file(out);
    let _ = fs::remove_file(json);
}

#[test]
#[ignore = "necesita testdata/muestra/firmado_10s.ts"]
fn pts_cambiado() {
    let mut data = fs::read("testdata/muestra/firmado_10s.ts").unwrap();
    let mut video_frames = 0;

    for i in (0..data.len() - 20).step_by(188) {
        let pid = (((data[i + 1] & 0x1F) as u16) << 8) | (data[i + 2] as u16);
        let pusi = (data[i + 1] & 0x40) != 0;
        if pid == 0x0100 && pusi {
            video_frames += 1;
            if video_frames == 61 {
                data[i + 17] ^= 0x01;
                break;
            }
        }
    }

    let out = get_temp_path("pts_cambiado.ts");
    let json = get_temp_path("pts_cambiado.json");
    fs::write(&out, &data).unwrap();
    let (code, _) = run_verify(&out, Some(&json));
    assert_eq!(code, Some(1));
    check_json_reason(&json, "INCOMPLETO");
    let _ = fs::remove_file(out);
    let _ = fs::remove_file(json);
}
