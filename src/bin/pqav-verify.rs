// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use clap::Parser;
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
/*
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
}*/

fn main() {
    let _args = Args::parse();
}
