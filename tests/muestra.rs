use std::fs;
use std::process::Command;

fn verificar(fichero: &str) -> Option<i32> {
    Command::new(env!("CARGO_BIN_EXE_pqav-verify"))
        .args([
            "--pub",
            "testdata/muestra/fuente.pub",
            "--in",
            fichero,
            "--quiet",
        ])
        .output()
        .ok()?
        .status
        .code()
}

#[test]
fn muestra_autentica() {
    assert_eq!(verificar("testdata/muestra/firmado_10s.ts"), Some(0));
}

#[test]
fn muestra_manipulada() {
    let input = "testdata/muestra/firmado_10s.ts";
    let out_path =
        std::env::temp_dir().join(format!("muestra_manipulada_{}.ts", std::process::id()));
    let mut data = fs::read(input).expect("Falta la muestra");
    let mut cambiado = false;

    for i in (0..data.len()).step_by(188) {
        if data[i] == 0x47
            && (data[i + 1] & 0x1F) == 0x01
            && data[i + 2] == 0x00
            && (data[i + 1] & 0x40) == 0
            && (data[i + 3] & 0x30) == 0x10
        {
            data[i + 4] ^= 0xFF;
            cambiado = true;
            break;
        }
    }

    assert!(cambiado, "No se encontró ningún paquete para cambiar");
    fs::write(&out_path, data).unwrap();
    assert_eq!(verificar(out_path.to_str().unwrap()), Some(1));
    let _ = fs::remove_file(out_path);
}
