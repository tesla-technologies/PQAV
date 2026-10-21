// SPDX-License-Identifier: MIT OR Apache-2.0
// src/cose.rs

use core::convert::Infallible;
pub use ml_dsa::{MlDsa44, Signature, Signer, SigningKey, VerifyingKey};

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

pub fn sig_structure(payload: &[u8]) -> Result<Vec<u8>, CoseError> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(4)?;
    e.str("Signature1")?;
    e.bytes(&PROTECTED)?;
    e.bytes(&[])?;
    e.bytes(payload)?;
    Ok(e.into_writer())
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
                0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31, 0x44,
                0xA1, 0x01, 0x38, 0x2F, 0x40, 0x59, 0x01, 0x2E
            ]
        );
    }
}
