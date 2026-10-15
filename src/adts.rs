// SPDX-License-Identifier: MIT OR Apache-2.0
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AdtsError {
    #[error("ADTS sin sincronía")]
    SinSincronia,
    #[error("ADTS con layer distinto de 0")]
    Layer,
    #[error("audio que no es de 48 kHz (sampling_frequency_index {0})")]
    Frecuencia(u8),
    #[error("ADTS con varios bloques por trama")]
    VariosBloques,
    #[error("trama ADTS cortada")]
    Cortada,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdtsFrame<'a> {
    pub profile: u8,
    pub sf_index: u8,
    pub channels: u8,
    pub raw: &'a [u8],
}

pub fn split_adts(pes_payload: &[u8]) -> Result<Vec<AdtsFrame<'_>>, AdtsError> {
    let mut tramas = Vec::new();
    let mut pos = 0;
    let len = pes_payload.len();

    while pos < len {
        if len - pos < 7 {
            return Err(AdtsError::Cortada);
        }
        let b = &pes_payload[pos..pos + 7];
        let syncword = ((b[0] as u16) << 4) | ((b[1] as u16) >> 4);
        if syncword != 0xFFF {
            return Err(AdtsError::SinSincronia);
        }

        let layer = (b[1] >> 1) & 0x03;
        if layer != 0 {
            return Err(AdtsError::Layer);
        }

        let protection_absent = b[1] & 0x01;
        let profile = (b[2] >> 6) & 0x03;
        let sf_index = (b[2] >> 2) & 0x0F;
        if sf_index != 3 {
            return Err(AdtsError::Frecuencia(sf_index));
        }

        let channels = ((b[2] & 0x01) << 2) | ((b[3] >> 6) & 0x03);
        let frame_length = (((b[3] & 0x03) as usize) << 11)
            | ((b[4] as usize) << 3)
            | ((b[5] as usize) >> 5);

        let raw_blocks = b[6] & 0x03;
        if raw_blocks != 0 {
            return Err(AdtsError::VariosBloques);
        }

        let hdr = if protection_absent == 1 { 7 } else { 9 };
        if frame_length < hdr || pos + frame_length > len {
            return Err(AdtsError::Cortada);
        }

        tramas.push(AdtsFrame {
            profile,
            sf_index,
            channels,
            raw: &pes_payload[pos + hdr..pos + frame_length],
        });

        pos += frame_length;
    }

    Ok(tramas)
}

pub fn enc_a(f: &AdtsFrame) -> Vec<u8> {
    let mut v = Vec::with_capacity(3 + f.raw.len());
    v.push(f.profile);
    v.push(f.sf_index);
    v.push(f.channels);
    v.extend_from_slice(f.raw);
    v
}

pub fn hash_audio(f: &AdtsFrame) -> [u8; 32] {
    let e = enc_a(f);
    let mut h = Sha256::new();
    h.update([0x02]);
    h.update(&e);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trama() -> Vec<u8> {
        let mut t = vec![0xFF, 0xF1, 0x4C, 0x80, 0x02, 0xFF, 0xFC];
        t.extend(0u8..16);
        t
    }

    #[test]
    fn u6_lo_que_se_firma_de_la_cabecera() {
        let a = trama();
        let fa = split_adts(&a).unwrap();
        assert_eq!(fa.len(), 1);
        assert_eq!((fa[0].profile, fa[0].sf_index, fa[0].channels, fa[0].raw.len()), (1, 3, 2, 16));
        assert_eq!(enc_a(&fa[0])[..3], [1, 3, 2]);
        let mut b = trama();
        b[5] = (b[5] & 0xE0) | 0x04;
        b[6] = 0x00;
        let fb = split_adts(&b).unwrap();
        assert_eq!(hash_audio(&fa[0]), hash_audio(&fb[0]));
        let mut c = trama();
        c[3] = (c[3] & 0x3F) | 0x40;
        let fc = split_adts(&c).unwrap();
        assert_ne!(hash_audio(&fa[0]), hash_audio(&fc[0]));
    }

    #[test]
    fn u7_solo_48_khz() {
        let mut t = trama();
        t[2] = (t[2] & 0xC3) | (4 << 2);
        assert_eq!(split_adts(&t), Err(AdtsError::Frecuencia(4)));
        let t = trama();
        assert_eq!(split_adts(&t[..20]), Err(AdtsError::Cortada));
        let mut dos = trama();
        dos.extend(trama());
        assert_eq!(split_adts(&dos).unwrap().len(), 2);
    }
}
