// SPDX-License-Identifier: MIT OR Apache-2.0
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum H264Error {
    #[error("datos antes del primer código de inicio")]
    DatosAntesDelInicio,
    #[error("más de un access unit por PES")]
    VariosAccessUnits,
}

pub fn enc_v(au: &[u8]) -> Result<Vec<u8>, H264Error> {
    let mut slices = Vec::new();
    let mut i = 0;
    let mut last_start = None;

    while i + 2 < au.len() {
        if au[i] == 0x00 && au[i + 1] == 0x00 && au[i + 2] == 0x01 {
            if let Some(start) = last_start {
                slices.push(&au[start..i]);
            } else {
                let prefix = &au[..i];
                if prefix.iter().any(|&b| b != 0) {
                    return Err(H264Error::DatosAntesDelInicio);
                }
            }
            last_start = Some(i + 3);
            i += 3;
        } else {
            i += 1;
        }
    }

    if let Some(start) = last_start {
        slices.push(&au[start..]);
    } else if au.iter().any(|&b| b != 0) {
        return Err(H264Error::DatosAntesDelInicio);
    }

    let mut salida = Vec::new();
    let mut auds = 0;

    for slice in slices {
        let mut end = slice.len();
        while end > 0 && slice[end - 1] == 0x00 {
            end -= 1;
        }
        let trimmed = &slice[..end];
        if trimmed.is_empty() {
            continue;
        }

        let nal_type = trimmed[0] & 0x1F;
        if nal_type == 9 {
            auds += 1;
            continue;
        }
        if nal_type == 12 {
            continue;
        }

        let len_be = (trimmed.len() as u32).to_be_bytes();
        salida.extend_from_slice(&len_be);
        salida.extend_from_slice(trimmed);
    }

    if auds > 1 {
        return Err(H264Error::VariosAccessUnits);
    }

    Ok(salida)
}

pub fn hash_video(au: &[u8]) -> Result<[u8; 32], H264Error> {
    let e = enc_v(au)?;
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(&e);
    Ok(h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const AU: [u8; 30] = [
        0x00, 0x00, 0x00, 0x01, 0x09, 0xF0, // AUD
        0x00, 0x00, 0x00, 0x01, 0x67, 0x64, 0x00, 0x28, 0xAC, // SPS
        0x00, 0x00, 0x01, 0x68, 0xEE, 0x3C, 0x80, // PPS
        0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x00, 0x00, // slice IDR + 2 ceros
    ];
    const ENC: [u8; 24] = [
        0x00, 0x00, 0x00, 0x05, 0x67, 0x64, 0x00, 0x28, 0xAC, 0x00, 0x00, 0x00, 0x04, 0x68, 0xEE, 0x3C,
        0x80, 0x00, 0x00, 0x00, 0x03, 0x65, 0x88, 0x84,
    ];

    #[test]
    fn u4_enc_v_ejemplo_del_02() {
        assert_eq!(enc_v(&AU).unwrap(), ENC.to_vec());
        let limpio = [
            0x00, 0x00, 0x01, 0x67, 0x64, 0x00, 0x28, 0xAC, 0x00, 0x00, 0x01, 0x68, 0xEE, 0x3C, 0x80,
            0x00, 0x00, 0x01, 0x65, 0x88, 0x84,
        ];
        assert_eq!(hash_video(&AU).unwrap(), hash_video(&limpio).unwrap());
        assert_eq!(
            hex::encode(hash_video(&AU).unwrap()),
            "f210c6e5cf4b27796a96271f89134e5905b8f52d2cc94cd5b49779ea6dffcac1"
        );
    }

    #[test]
    fn u5_un_byte_cambia_el_hash() {
        let mut otro = AU;
        otro[27] ^= 0x01;
        assert_ne!(hash_video(&AU).unwrap(), hash_video(&otro).unwrap());
        let mut dos_aud = AU.to_vec();
        dos_aud.extend_from_slice(&[0x00, 0x00, 0x01, 0x09, 0xF0]);
        assert_eq!(enc_v(&dos_aud), Err(H264Error::VariosAccessUnits));
        assert_eq!(enc_v(&[0x12, 0x00, 0x00, 0x01, 0x65, 0x88]), Err(H264Error::DatosAntesDelInicio));
    }
}
