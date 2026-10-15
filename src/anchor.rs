// src/anchor.rs
use core::convert::Infallible;

pub const VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorPayload {
    pub stream_id: [u8; 16],
    pub counter: u64,
    pub prev: [u8; 32],
    pub components: Vec<(u8, String, u8)>,
    pub units: Vec<(u8, u32, [u8; 32])>, // (comp, rel, hash)
    pub is_final: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum AnchorError {
    #[error("error al escribir CBOR: {0}")]
    Encode(#[from] minicbor::encode::Error<Infallible>),
    #[error("error al leer CBOR: {0}")]
    Decode(#[from] minicbor::decode::Error),
    #[error("clave inesperada: se esperaba {esperada} y llega {leida}")]
    ClaveInesperada { esperada: u8, leida: u8 },
    #[error("tamaño incorrecto en {0}")]
    Tamano(&'static str),
    #[error("versión desconocida: {0}")]
    Version(u8),
    #[error("componente {0} fuera del mapa")]
    ComponenteFuera(u8),
    #[error("lista de longitud indefinida")]
    Indefinida,
    #[error("sobran bytes al final de la carga")]
    Sobra,
    #[error("carga no canónica")]
    NoCanonica,
}

pub fn encode(p: &AnchorPayload) -> Result<Vec<u8>, AnchorError> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.map(7)?;
    e.u8(1)?.u8(VERSION)?; // version
    e.u8(2)?.bytes(&p.stream_id)?;
    e.u8(3)?.u64(p.counter)?;
    e.u8(4)?.bytes(&p.prev)?;
    e.u8(5)?.array(p.components.len() as u64)?;
    for (st, lang, at) in &p.components {
        e.array(3)?.u8(*st)?.str(lang)?.u8(*at)?;
    }
    e.u8(6)?.array(p.units.len() as u64)?;
    for (c, r, h) in &p.units {
        e.array(3)?.u8(*c)?.u32(*r)?.bytes(h)?;
    }
    e.u8(7)?.bool(p.is_final)?;
    Ok(e.into_writer())
}

pub fn decode_strict(b: &[u8]) -> Result<AnchorPayload, AnchorError> {
    let mut d = minicbor::Decoder::new(b);

    let n_map = d.map()?.ok_or(AnchorError::Indefinida)?;
    if n_map != 7 {
        return Err(AnchorError::NoCanonica);
    }

    let k1 = d.u8()?;
    if k1 != 1 {
        return Err(AnchorError::ClaveInesperada {
            esperada: 1,
            leida: k1,
        });
    }
    let version = d.u8()?;
    if version != VERSION {
        return Err(AnchorError::Version(version));
    }

    let k2 = d.u8()?;
    if k2 != 2 {
        return Err(AnchorError::ClaveInesperada {
            esperada: 2,
            leida: k2,
        });
    }
    let sid_bytes = d.bytes()?;
    let stream_id: [u8; 16] =
        <[u8; 16]>::try_from(sid_bytes).map_err(|_| AnchorError::Tamano("stream_id"))?;

    let k3 = d.u8()?;
    if k3 != 3 {
        return Err(AnchorError::ClaveInesperada {
            esperada: 3,
            leida: k3,
        });
    }
    let counter = d.u64()?;

    let k4 = d.u8()?;
    if k4 != 4 {
        return Err(AnchorError::ClaveInesperada {
            esperada: 4,
            leida: k4,
        });
    }

    let prev_bytes = d.bytes()?;
    let prev: [u8; 32] =
        <[u8; 32]>::try_from(prev_bytes).map_err(|_| AnchorError::Tamano("prev"))?;

    let k5 = d.u8()?;
    if k5 != 5 {
        return Err(AnchorError::ClaveInesperada {
            esperada: 5,
            leida: k5,
        });
    }
    let comp_len = d.array()?.ok_or(AnchorError::Indefinida)?;
    let mut components = Vec::with_capacity(comp_len as usize);
    for _ in 0..comp_len {
        let item_len = d.array()?.ok_or(AnchorError::Indefinida)?;
        if item_len != 3 {
            return Err(AnchorError::NoCanonica);
        }
        let st = d.u8()?;
        let lang = d.str()?.to_string();
        if !lang.is_empty() && lang.len() != 3 {
            return Err(AnchorError::Tamano("lang"));
        }
        let at = d.u8()?;
        components.push((st, lang, at));
    }

    let k6 = d.u8()?;
    if k6 != 6 {
        return Err(AnchorError::ClaveInesperada {
            esperada: 6,
            leida: k6,
        });
    }
    let units_len = d.array()?.ok_or(AnchorError::Indefinida)?;
    let mut units = Vec::with_capacity(units_len as usize);
    for _ in 0..units_len {
        let item_len = d.array()?.ok_or(AnchorError::Indefinida)?;
        if item_len != 3 {
            return Err(AnchorError::NoCanonica);
        }
        let c = d.u8()?;
        if c as usize >= components.len() {
            return Err(AnchorError::ComponenteFuera(c));
        }
        let r = d.u32()?;
        let h_bytes = d.bytes()?;
        let hash: [u8; 32] =
            <[u8; 32]>::try_from(h_bytes).map_err(|_| AnchorError::Tamano("hash"))?;
        units.push((c, r, hash));
    }

    let k7 = d.u8()?;
    if k7 != 7 {
        return Err(AnchorError::ClaveInesperada {
            esperada: 7,
            leida: k7,
        });
    }
    let is_final = d.bool()?;

    if d.position() != b.len() {
        return Err(AnchorError::Sobra);
    }

    let res = AnchorPayload {
        stream_id,
        counter,
        prev,
        components,
        units,
        is_final,
    };

    let re_encoded = encode(&res)?;
    if re_encoded != b {
        return Err(AnchorError::NoCanonica);
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn carga_de_prueba(counter: u64, con_audio: bool) -> AnchorPayload {
        let mut stream_id = [0u8; 16];
        for (i, b) in stream_id.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut components = vec![(27u8, String::new(), 0u8)];
        let mut units = Vec::new();
        for (i, r) in [0u32, 3_600, 7_200, 10_800, 14_400, 18_000]
            .iter()
            .enumerate()
        {
            units.push((0u8, *r, [i as u8; 32]));
        }
        if con_audio {
            components.push((15, "spa".to_string(), 0));
            for k in 0..8u32 {
                units.push((1u8, 1_920 * (k + 1), [0xA0 + k as u8; 32]));
            }
        }
        AnchorPayload {
            stream_id,
            counter,
            prev: [0; 32],
            components,
            units,
            is_final: false,
        }
    }

    #[test]
    fn u8_carga_ida_y_vuelta() {
        let p = carga_de_prueba(0, true);
        let b = encode(&p).unwrap();
        assert_eq!(b[..5], [0xA7, 0x01, 0x01, 0x02, 0x50]);
        assert_eq!(b[21..26], [0x03, 0x00, 0x04, 0x58, 0x20]);
        assert_eq!(decode_strict(&b).unwrap(), p);
        assert_eq!(encode(&decode_strict(&b).unwrap()).unwrap(), b);
        assert_eq!(encode(&carga_de_prueba(0, false)).unwrap().len(), 301);
        assert_eq!(encode(&carga_de_prueba(24, false)).unwrap().len(), 302);
        assert_eq!(
            encode(&carga_de_prueba(24, true)).unwrap().len(),
            302 + 7 + 8 * 39
        );
    }

    #[test]
    fn u9_forma_larga_rechazada() {
        let b = encode(&carga_de_prueba(0, true)).unwrap();
        let mut larga = vec![0xA7, 0x01, 0x18, 0x01];
        larga.extend_from_slice(&b[3..]);
        assert!(decode_strict(&larga).is_err());
        let mut sobra = b.clone();
        sobra.push(0x00);
        assert!(decode_strict(&sobra).is_err());
    }
}
