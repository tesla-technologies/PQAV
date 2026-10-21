// SPDX-License-Identifier: MIT OR Apache-2.0
// src/bin/pqav-keygen.rs

use clap::Parser;
use pqav::keys::generar;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(version, about = "Crea un par de claves ML-DSA-44")]
struct Args{
    #[arg(long, value_name = "PREFIJO")]
    out: PathBuf,

    #[arg(long)]
    force:bool,
}

fn main() -> ExitCode{
    let args = Args::parse();
    match generar(&args.out, args.force) {
	Ok(g) => {
	    println!("semilla:        {}", g.seed_path.display());
            println!("clave pública: {}", g.pub_path.display());
            println!("kid:            {}", hex::encode(g.kid));
            ExitCode::SUCCESS
	}
	Err(e) => {
	    eprintln!("pqav-keygen: error: {e}");
            ExitCode::from(2)
	}	
    }
}
