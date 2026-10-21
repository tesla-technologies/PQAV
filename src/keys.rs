// SPDX-License-Identifier: MIT OR Apache-2.0
// src/keys.rs
use ml_dsa::{EncodedVerifyingKey, Keypair, MlDsa44, Seed, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

pub const PUB_LEN: usize = 1312;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("no se puede {accion} {ruta}: {fuente}")]
    Io {
        accion: &'static str,
        ruta: String,
        #[source]
        fuente: std::io::Error,
    },
    #[error("el fichero {0} ya existe (usa --force para sobrescribirlo)")]
    YaExiste(String),
    #[error("semilla inválida en {0}: tienen que ser 64 caracteres hexadecimales")]
    SemillaInvalida(String),
    #[error("clave pública inválida en {ruta}: mide {len} bytes y tiene que medir 1312")]
    PubInvalida { ruta: String, len: usize },
    #[error("no se ha podido obtener aleatoriedad del sistema")]
    Aleatorio,
}

pub struct Generadas {
    pub seed_path: PathBuf,
    pub pub_path: PathBuf,
    pub kid: [u8; 8],
}

pub fn kid_of(vk_bytes: &[u8]) -> [u8; 8] {
    let hash = Sha256::digest(vk_bytes);
    let mut kid = [0u8; 8];
    kid.copy_from_slice(&hash[..8]);
    kid
}

pub fn generar(prefijo: &Path, force: bool) -> Result<Generadas, KeyError> {
    let mut s = prefijo.as_os_str().to_owned();
    s.push(".seed");
    let seed_path = PathBuf::from(s);

    let mut p = prefijo.as_os_str().to_owned();
    p.push(".pub");
    let pub_path = PathBuf::from(p);

    if !force {
        if seed_path.exists() {
            return Err(KeyError::YaExiste(seed_path.display().to_string()));
        }
        if pub_path.exists() {
            return Err(KeyError::YaExiste(pub_path.display().to_string()));
        }
    }

    let mut semilla = [0u8; 32];
    getrandom::fill(&mut semilla).map_err(|_| KeyError::Aleatorio)?;

    let sk = SigningKey::<MlDsa44>::from_seed(&Seed::from(semilla));
    let vk = sk.verifying_key();
    let vk_bytes = vk.encode();

    let seed_content = format!("{}\n", hex::encode(semilla));

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&seed_path)
            .map_err(|e| KeyError::Io {
                accion: "escribir",
                ruta: seed_path.display().to_string(),
                fuente: e,
            })?;

        file.write_all(seed_content.as_bytes())
            .map_err(|e| KeyError::Io {
                accion: "escribir",
                ruta: seed_path.display().to_string(),
                fuente: e,
            })?;

        let _ = std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600));
    }

    #[cfg(not(unix))]
    {
        std::fs::write(&seed_path, seed_content.as_bytes()).map_err(|e| KeyError::Io {
            accion: "escribir",
            ruta: seed_path.display().to_string(),
            fuente: e,
        })?;
    }

    std::fs::write(&pub_path, vk_bytes.as_slice()).map_err(|e| KeyError::Io {
        accion: "escribir",
        ruta: pub_path.display().to_string(),
        fuente: e,
    })?;

    let kid = kid_of(&vk_bytes);
    Ok(Generadas {
        seed_path,
        pub_path,
        kid,
    })
}

pub fn leer_seed(ruta: &Path) -> Result<(SigningKey<MlDsa44>, [u8; 8]), KeyError> {
    let texto = std::fs::read_to_string(ruta).map_err(|e| KeyError::Io {
        accion: "leer",
        ruta: ruta.display().to_string(),
        fuente: e,
    })?;

    let trimmed = texto.trim_end();
    if trimmed.len() != 64 {
        return Err(KeyError::SemillaInvalida(ruta.display().to_string()));
    }

    let bytes = hex::decode(trimmed)
        .map_err(|_| KeyError::SemillaInvalida(ruta.display().to_string()))?;

    let mut semilla = [0u8; 32];
    semilla.copy_from_slice(&bytes);
    let sk = SigningKey::<MlDsa44>::from_seed(&Seed::from(semilla));
    let kid = kid_of(&sk.verifying_key().encode());
    Ok((sk, kid))
}

pub fn leer_pub(ruta: &Path) -> Result<(VerifyingKey<MlDsa44>, [u8; 8]), KeyError> {
    let bytes = std::fs::read(ruta).map_err(|e| KeyError::Io {
        accion: "leer",
        ruta: ruta.display().to_string(),
        fuente: e,
    })?;

    if bytes.len() != PUB_LEN {
        return Err(KeyError::PubInvalida {
            ruta: ruta.display().to_string(),
            len: bytes.len(),
        });
    }

    let enc = EncodedVerifyingKey::<MlDsa44>::try_from(bytes.as_slice()).map_err(|_| {
        KeyError::PubInvalida {
            ruta: ruta.display().to_string(),
            len: bytes.len(),
        }
    })?;

    let vk = VerifyingKey::<MlDsa44>::decode(&enc);
    let kid = kid_of(&bytes);
    Ok((vk, kid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn m5_claves_ida_y_vuelta() {
        let dir = std::env::temp_dir().join(format!("pqav-m5-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let g = generar(&dir.join("k"), false).unwrap();
        assert!(matches!(
            generar(&dir.join("k"), false),
            Err(KeyError::YaExiste(_))
        ));
        assert_eq!(std::fs::read(&g.seed_path).unwrap().len(), 65);
        assert_eq!(std::fs::read(&g.pub_path).unwrap().len(), 1312);
        let (_, kid_s) = leer_seed(&g.seed_path).unwrap();
        let (_, kid_p) = leer_pub(&g.pub_path).unwrap();
        assert_eq!(kid_s, g.kid);
        assert_eq!(kid_p, g.kid);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
