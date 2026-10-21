// SPDX-License-Identifier: MIT OR Apache-2.0
// src/cose.rs

use core::convert::Infallible;
use minicbor::data::Tag;
pub use ml_dsa::{MlDsa44, Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

pub const PROTECTED: [u8; 4] = [0xA1, 0x01, 0x38, 0x2F];
pub const SIG_LEN: usize = 2420;

#[derive(Debug, thiserror::Error)]
pub enum CoseError {
    #[error("COSE mal formado: {0}")]
    MalFormado(&'static str),
    #[error("kid desconocido")]
    KidDesconocido,
    #[error("firma no válida")]
    FirmaNoValida,
    #[error("error al escribir CBOR: {0}")]
    Encode(#[from] minicbor::encode::Error<Infallible>),
    #[error("error al firmar")]
    Firmar,
}

impl From<minicbor::decode::Error> for CoseError {
    fn from(_: minicbor::decode::Error) -> Self {
        CoseError::MalFormado("CBOR ilegible")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub payload: Vec<u8>,
    pub hash_cose: [u8; 32],
}

pub fn sig_structure(payload: &[u8]) -> Result<Vec<u8>, CoseError> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(4)?;
    e.str("Signature1")?;
    e.bytes(&PROTECTED)?;
    e.bytes(&[])?;
    e.bytes(payload)?;
    Ok(e.into_writer())
}

pub fn sign(sk: &SigningKey<MlDsa44>, kid: &[u8; 8], payload: &[u8]) -> Result<Vec<u8>, CoseError> {
    let to_sign = sig_structure(payload)?;
    let sig: Signature<MlDsa44> = sk.try_sign(&to_sign).map_err(|_| CoseError::Firmar)?;
    let sig_bytes = sig.encode();

    let mut e = minicbor::Encoder::new(Vec::new());
    e.tag(Tag::new(18))?;
    e.array(4)?;
    e.bytes(&PROTECTED)?;
    e.map(1)?;
    e.u8(4)?;
    e.bytes(kid)?;
    e.bytes(payload)?;
    e.bytes(&sig_bytes[..])?;
    Ok(e.into_writer())
}

pub fn verify(
    vk: &VerifyingKey<MlDsa44>,
    kid: &[u8; 8],
    cose: &[u8],
) -> Result<Verified, CoseError> {
    let mut d = minicbor::Decoder::new(cose);

    let tag = d.tag()?;
    if tag != Tag::new(18) {
        return Err(CoseError::MalFormado("etiqueta inesperada"));
    }

    let array_len = d.array()?;
    if array_len != Some(4) {
        return Err(CoseError::MalFormado("array no tiene 4 elementos"));
    }

    let protected = d.bytes()?;
    if protected != PROTECTED {
        return Err(CoseError::MalFormado("cabecera protegida no válida"));
    }

    let map_len = d.map()?;
    if map_len != Some(1) {
        return Err(CoseError::MalFormado(
            "cabecera no protegida debe tener 1 elemento",
        ));
    }

    let key = d.u8()?;
    if key != 4 {
        return Err(CoseError::MalFormado(
            "clave de abecera no protegida debe ser 4",
        ));
    }

    let kid_read = d.bytes()?;
    if kid_read.len() != 8 {
        return Err(CoseError::MalFormado("kid debe medir 8 bytes"));
    }

    let payload = d.bytes()?;

    let sig_bytes = d.bytes()?;
    if sig_bytes.len() != SIG_LEN {
        return Err(CoseError::MalFormado("firma debe medir 2420 bytes"));
    }

    if d.position() != cose.len() {
        return Err(CoseError::MalFormado("sobran bytes"));
    }

    let mut re_enc = minicbor::Encoder::new(Vec::with_capacity(cose.len()));
    re_enc.tag(Tag::new(18))?;
    re_enc.array(4)?;
    re_enc.bytes(protected)?;
    re_enc.map(1)?;
    re_enc.u8(4)?;
    re_enc.bytes(kid_read)?;
    re_enc.bytes(payload)?;
    re_enc.bytes(sig_bytes)?;

    if re_enc.into_writer() != cose {
        return Err(CoseError::MalFormado("sobre no canónico"));
    }

    if kid_read != kid {
        return Err(CoseError::KidDesconocido);
    }

    let to_sign = sig_structure(payload)?;
    let sig = Signature::<MlDsa44>::try_from(sig_bytes).map_err(|_| CoseError::FirmaNoValida)?;
    if !vk.verify_with_context(&to_sign, &[], &sig) {
        return Err(CoseError::FirmaNoValida);
    }

    let hash_cose = Sha256::digest(cose).into();
    Ok(Verified {
        payload: payload.to_vec(),
        hash_cose,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::kid_of;
    use ml_dsa::{Keypair, Seed};

    fn claves() -> (SigningKey<MlDsa44>, VerifyingKey<MlDsa44>, [u8; 8]) {
        let sk = SigningKey::<MlDsa44>::from_seed(&Seed::from([7u8; 32]));
        let vk = sk.verifying_key();
        let kid = kid_of(&vk.encode());
        (sk, vk, kid)
    }

    #[test]
    fn u11_tamanos() {
        let (sk, vk, _) = claves();
        assert_eq!(vk.encode().len(), 1312);
        let sig: Signature<MlDsa44> = sk.try_sign(b"hola").unwrap();
        assert_eq!(sig.encode().len(), 2420);
        assert_eq!(
            sig_structure(&[0u8; 302]).unwrap()[..21],
            [
                0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31, 0x44, 0xA1,
                0x01, 0x38, 0x2F, 0x40, 0x59, 0x01, 0x2E
            ]
        );
    }

    #[test]
    fn u10_firmar_y_verificar() {
        let (sk, vk, kid) = claves();
        let carga = vec![0x42u8; 748];
        let cose = sign(&sk, &kid, &carga).unwrap();
        assert_eq!(cose.len(), 748 + 2444);
        assert_eq!(
            cose[..11],
            [0xD2, 0x84, 0x44, 0xA1, 0x01, 0x38, 0x2F, 0xA1, 0x04, 0x48, kid[0]]
        );

        let ok = verify(&vk, &kid, &cose).unwrap();
        assert_eq!(ok.payload, carga);
        assert_eq!(sign(&sk, &kid, &carga).unwrap(), cose);

        let mut c = cose.clone();
        c[21 + 100] ^= 0x01;
        assert!(matches!(
            verify(&vk, &kid, &c),
            Err(CoseError::FirmaNoValida)
        ));

        let mut c = cose.clone();
        c[6] = 0x2E;
        assert!(matches!(
            verify(&vk, &kid, &c),
            Err(CoseError::MalFormado(_))
        ));

        let mut c = cose.clone();
        let n = c.len() - 1;
        c[n] ^= 0xFF;
        assert!(matches!(
            verify(&vk, &kid, &c),
            Err(CoseError::FirmaNoValida)
        ));

        assert!(matches!(
            verify(&vk, &[0u8; 8], &cose),
            Err(CoseError::KidDesconocido)
        ));
    }
}
