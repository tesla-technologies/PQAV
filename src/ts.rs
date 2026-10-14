// src/ts.rs
// SPDX-License-Identifier: MIT OR Apache-2.0

pub const TS: usize = 188;
pub const PAT_PID: u16 = 0x0000;
pub const NULL_PID: u16 = 0x1FFF;
pub const PTS_MOD: u64 = 1 << 33;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TsError {
    #[error("paquete sin sincronía")]
    SinSincronia,
    #[error("paquete con error de transporte")]
    ErrorTransporte,
    #[error("campo de adaptación inválido")]
    CampoAdaptacion,
    #[error("sección mal formada")]
    SeccionMal,
    #[error("CRC incorrecto")]
    Crc,
    #[error("tabla inesperada: table_id 0x{0:02X}")]
    TablaInesperada(u8),
    #[error("el MVP solo admite un programa")]
    VariosProgramas,
    #[error("PES sin código de inicio")]
    PesSinInicio,
    #[error("PES demasiado corto")]
    PesCorto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet<'a> {
    pub pid: u16,
    pub pusi: bool,
    pub cc: u8,
    pub payload: &'a [u8], // carga útil, ya sin cabecera ni campo de adaptación
}

#[derive(Debug, Default)]
pub struct SectionAssembler {
    buf: Vec<u8>,
    open: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EsEntry {
    pub stream_type: u8,
    pub pid: u16,
    pub descriptors: Vec<(u8, Vec<u8>)>, // (etiqueta, datos sin etiqueta ni longitud)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pmt {
    pub version: u8,
    pub pcr_pid: u16,
    pub es: Vec<EsEntry>,
}

pub fn parse_packet(p: &[u8]) -> Result<Packet<'_>, TsError> {
    if p.len() != 188 || p[0] != 0x47 {
        return Err(TsError::SinSincronia);
    }
    if (p[1] & 0x80) != 0 {
        return Err(TsError::ErrorTransporte);
    }

    let pid = (((p[1] & 0x1F) as u16) << 8) | (p[2] as u16);
    let pusi = (p[1] & 0x40) != 0;
    let afc = (p[3] >> 4) & 0x03;
    let cc = p[3] & 0x0F;

    let mut inicio = 4;
    if afc == 2 || afc == 3 {
        inicio = 5 + (p[4] as usize);
    }

    if inicio > 188 {
        return Err(TsError::CampoAdaptacion);
    }

    let payload = if afc == 0 || afc == 2 {
        &p[188..188]
    } else {
        &p[inicio..188]
    };

    Ok(Packet {
        pid,
        pusi,
        cc,
        payload,
    })
}

pub fn crc32_mpeg(data: &[u8]) -> u32 {
    let mut crc = 0xFFFFFFFFu32;
    for &b in data {
        crc ^= (b as u32) << 24;
        for _ in 0..8 {
            if (crc & 0x80000000) != 0 {
                crc = (crc << 1) ^ 0x04C11DB7;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

impl SectionAssembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, pkt: &Packet) -> Option<Vec<u8>> {
        if pkt.pusi {
            if pkt.payload.is_empty() {
                return None;
            }
            let pointer = pkt.payload[0] as usize;
            if 1 + pointer > pkt.payload.len() {
                self.buf.clear();
                self.open = false;
                return None;
            }
            self.buf.clear();
            self.buf.extend_from_slice(&pkt.payload[1 + pointer..]);
            self.open = true;
        } else if self.open {
            self.buf.extend_from_slice(pkt.payload);
        } else {
            return None;
        }

        if self.buf.len() >= 3 {
            let total = 3 + ((((self.buf[1] & 0x0F) as usize) << 8) | (self.buf[2] as usize));
            if self.buf.len() >= total {
                self.open = false;
                let section = self.buf[..total].to_vec();
                self.buf.drain(..total);
                return Some(section);
            }
        }

        None
    }
}

fn check_common_section(section: &[u8], expected_table_id: u8) -> Result<usize, TsError> {
    if section.len() < 12 {
        return Err(TsError::SeccionMal);
    }
    if section[0] != expected_table_id {
        return Err(TsError::TablaInesperada(section[0]));
    }
    let section_length = (((section[1] & 0x0F) as usize) << 8) | (section[2] as usize);
    if 3 + section_length != section.len() {
        return Err(TsError::SeccionMal);
    }
    if crc32_mpeg(section) != 0 {
        return Err(TsError::Crc);
    }
    Ok(section_length)
}

pub fn parse_pat(section: &[u8]) -> Result<u16, TsError> {
    let section_length = check_common_section(section, 0x00)?;

    let mut program_pids = Vec::new();
    let end = 3 + section_length - 4; // Excluye los 4 bytes del CRC

    let mut i = 8;
    while i < end {
        if i + 4 > end {
            return Err(TsError::SeccionMal);
        }
        let program_number = ((section[i] as u16) << 8) | (section[i + 1] as u16);
        let pid = (((section[i + 2] & 0x1F) as u16) << 8) | (section[i + 3] as u16);

        if program_number != 0 {
            program_pids.push(pid);
        }
        i += 4;
    }

    if program_pids.len() != 1 {
        return Err(TsError::VariosProgramas);
    }

    Ok(program_pids[0])
}

pub fn parse_pmt(section: &[u8]) -> Result<Pmt, TsError> {
    let section_length = check_common_section(section, 0x02)?;

    let version = (section[5] >> 1) & 0x1F;
    let pcr_pid = (((section[8] & 0x1F) as u16) << 8) | (section[9] as u16);
    let program_info_length = (((section[10] & 0x0F) as usize) << 8) | (section[11] as usize);

    let mut i = 12 + program_info_length;
    let fin = 3 + section_length - 4; // Excluye los 4 bytes del CRC

    if i > fin {
        return Err(TsError::SeccionMal);
    }

    let mut es = Vec::new();

    while i < fin {
        if i + 5 > fin {
            return Err(TsError::SeccionMal);
        }
        let stream_type = section[i];
        let pid = (((section[i + 1] & 0x1F) as u16) << 8) | (section[i + 2] as u16);
        let es_info_length = (((section[i + 3] & 0x0F) as usize) << 8) | (section[i + 4] as usize);

        if i + 5 + es_info_length > fin {
            return Err(TsError::SeccionMal);
        }

        let desc_start = i + 5;
        let desc_end = desc_start + es_info_length;
        let mut d_idx = desc_start;
        let mut descriptors = Vec::new();

        while d_idx < desc_end {
            if d_idx + 2 > desc_end {
                return Err(TsError::SeccionMal);
            }
            let tag = section[d_idx];
            let len = section[d_idx + 1] as usize;
            if d_idx + 2 + len > desc_end {
                return Err(TsError::SeccionMal);
            }
            let data = section[d_idx + 2..d_idx + 2 + len].to_vec();
            descriptors.push((tag, data));
            d_idx += 2 + len;
        }

        es.push(EsEntry {
            stream_type,
            pid,
            descriptors,
        });

        i += 5 + es_info_length;
    }

    Ok(Pmt {
        version,
        pcr_pid,
        es,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // PAT y PMT del fichero de prueba (documento 01, apartados 3.2 y 3.3)
    const PAT: [u8; 16] = [
        0x00, 0xB0, 0x0D, 0x00, 0x01, 0xC1, 0x00, 0x00, 0x00, 0x01, 0xF0, 0x00, 0x2A, 0xB1, 0x04,
        0xB2,
    ];
    const PMT: [u8; 32] = [
        0x02, 0xB0, 0x1D, 0x00, 0x01, 0xC1, 0x00, 0x00, 0xE1, 0x00, 0xF0, 0x00, 0x1B, 0xE1, 0x00,
        0xF0, 0x00, 0x0F, 0xE1, 0x01, 0xF0, 0x06, 0x0A, 0x04, 0x73, 0x70, 0x61, 0x00, 0x48, 0x33,
        0x2B, 0x84,
    ];

    #[test]
    fn u1_crc32_valor_de_control() {
        assert_eq!(crc32_mpeg(b"123456789"), 0x0376_E6E7);
        assert_eq!(crc32_mpeg(&PAT), 0);
        assert_eq!(crc32_mpeg(&PAT[..12]), 0x2AB1_04B2);
    }

    #[test]
    fn m1_pat_y_pmt_de_ejemplo() {
        assert_eq!(parse_pat(&PAT), Ok(0x1000));
        let pmt = parse_pmt(&PMT).unwrap();
        assert_eq!(pmt.version, 0);
        assert_eq!(pmt.pcr_pid, 0x0100);
        assert_eq!(pmt.es.len(), 2);
        assert_eq!((pmt.es[0].stream_type, pmt.es[0].pid), (0x1B, 0x0100));
        assert_eq!((pmt.es[1].stream_type, pmt.es[1].pid), (0x0F, 0x0101));
        assert_eq!(pmt.es[1].descriptors, vec![(0x0A, b"spa\0".to_vec())]);
        let mut mala = PMT;
        mala[25] ^= 0x01; // una letra del idioma: el CRC ya no cuadra
        assert_eq!(parse_pmt(&mala), Err(TsError::Crc));
    }

    #[test]
    fn m1_paquete_y_seccion() {
        let mut p = [0xFFu8; 188];
        p[..5].copy_from_slice(&[0x47, 0x40, 0x00, 0x10, 0x00]);
        p[5..21].copy_from_slice(&PAT);
        let pkt = parse_packet(&p).unwrap();
        assert_eq!(
            (pkt.pid, pkt.pusi, pkt.cc, pkt.payload.len()),
            (0, true, 0, 184)
        );
        let mut sa = SectionAssembler::new();
        assert_eq!(sa.push(&pkt), Some(PAT.to_vec()));
        p[0] = 0x46;
        assert_eq!(parse_packet(&p), Err(TsError::SinSincronia));
    }

    #[test]
    fn u2_pts_ida_y_vuelta() {
        for x in [0u64, 123_456_789, (1u64 << 33) - 1] {
            assert_eq!(decode_pts(&encode_pts(x, 0b0010)), x);
        }
        assert_eq!(encode_pts(126_000, 0b0010), [0x21, 0x00, 0x07, 0xD8, 0x61]);
        assert_eq!(encode_pts(126_000, 0b0011), [0x31, 0x00, 0x07, 0xD8, 0x61]);
        assert_eq!(encode_pts(118_800, 0b0001), [0x11, 0x00, 0x07, 0xA0, 0x21]);
    }

    #[test]
    fn m2_pes_de_ejemplo() {
        // cabecera PES del primer frame (documento 01, apartado 4.4) seguida de una AUD
        let mut datos = vec![
            0x00, 0x00, 0x01, 0xE0, 0x00, 0x00, 0x80, 0xC0, 0x0A, 0x31, 0x00, 0x07, 0xD8, 0x61,
            0x11, 0x00, 0x07, 0xA0, 0x21,
        ];
        datos.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x09, 0xF0]);
        let pes = parse_pes(&RawPes {
            data: datos,
            first_packet: 7,
        })
        .unwrap();
        assert_eq!(pes.stream_id, 0xE0);
        assert_eq!(pes.pts, Some(126_000));
        assert_eq!(pes.payload, vec![0x00, 0x00, 0x00, 0x01, 0x09, 0xF0]);
        assert_eq!(pes.first_packet, 7);
        let corto = RawPes {
            data: vec![0x00, 0x00, 0x01, 0xE0, 0x00],
            first_packet: 0,
        };
        assert_eq!(parse_pes(&corto), Err(TsError::PesCorto));
    }

    #[test]
    fn u3_pts_dif_con_vuelta() {
        let m = 1u64 << 33;
        assert_eq!(pts_dif(5, m - 5), 10);
        assert_eq!(pts_dif(m - 5, 5), -10);
        assert_eq!(pts_dif(129_600, 126_000), 3_600);
        assert_eq!(pts_dif(126_000, 129_600), -3_600);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawPes {
    pub data: Vec<u8>,     // las cargas juntas, desde 00 00 01
    pub first_packet: u64, // número del paquete (desde 0) donde empezó
}

#[derive(Debug, Default)]
pub struct PesAssembler {
    buf: Vec<u8>,
    open: bool,
    first: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pes {
    pub stream_id: u8,
    pub pts: Option<u64>,
    pub payload: Vec<u8>, // lo que va después de la cabecera PES
    pub first_packet: u64,
}

impl PesAssembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, pkt: &Packet, index: u64) -> Option<RawPes> {
        if pkt.pusi {
            let prev = if self.open {
                Some(RawPes {
                    data: std::mem::take(&mut self.buf),
                    first_packet: self.first,
                })
            } else {
                None
            };
            self.buf.clear();
            self.buf.extend_from_slice(pkt.payload);
            self.open = true;
            self.first = index;
            prev
        } else {
            if self.open {
                self.buf.extend_from_slice(pkt.payload);
            }
            None
        }
    }

    pub fn finish(&mut self) -> Option<RawPes> {
        if self.open {
            self.open = false;
            Some(RawPes {
                data: std::mem::take(&mut self.buf),
                first_packet: self.first,
            })
        } else {
            None
        }
    }
}

pub fn parse_pes(raw: &RawPes) -> Result<Pes, TsError> {
    let b = &raw.data;
    if b.len() < 9 {
        return Err(TsError::PesCorto);
    }
    if b[0..3] != [0x00, 0x00, 0x01] {
        return Err(TsError::PesSinInicio);
    }

    let stream_id = b[3];
    let longitud = ((b[4] as usize) << 8) | (b[5] as usize);
    let flags2 = b[7];
    let hdr_len = b[8] as usize;

    if 9 + hdr_len > b.len() {
        return Err(TsError::PesCorto);
    }

    let pts = if (flags2 & 0x80) != 0 {
        if hdr_len < 5 {
            return Err(TsError::PesCorto);
        }
        Some(decode_pts(&b[9..14]))
    } else {
        None
    };

    let inicio_datos = 9 + hdr_len;
    let fin_datos = if longitud == 0 {
        b.len()
    } else {
        std::cmp::min(6 + longitud, b.len())
    };

    if fin_datos < inicio_datos {
        return Err(TsError::PesCorto);
    }

    let payload = b[inicio_datos..fin_datos].to_vec();

    Ok(Pes {
        stream_id,
        pts,
        payload,
        first_packet: raw.first_packet,
    })
}

pub fn encode_pts(pts: u64, prefix: u8) -> [u8; 5] {
    let b0 = ((prefix & 0x0F) << 4) | ((((pts >> 30) & 0x07) as u8) << 1) | 1;
    let b1 = ((pts >> 22) & 0xFF) as u8;
    let b2 = ((((pts >> 15) & 0x7F) as u8) << 1) | 1;
    let b3 = ((pts >> 7) & 0xFF) as u8;
    let b4 = (((pts & 0x7F) as u8) << 1) | 1;

    [b0, b1, b2, b3, b4]
}

pub fn decode_pts(b: &[u8]) -> u64 {
    let b0 = b[0] as u64;
    let b1 = b[1] as u64;
    let b2 = b[2] as u64;
    let b3 = b[3] as u64;
    let b4 = b[4] as u64;

    ((b0 >> 1) & 0x07) << 30
        | (b1 << 22)
        | ((b2 >> 1) & 0x7F) << 15
        | (b3 << 7)
        | ((b4 >> 1) & 0x7F)
}

pub fn pts_dif(a: u64, b: u64) -> i64 {
    (a as i64 - b as i64 + (1i64 << 32)).rem_euclid(1i64 << 33) - (1i64 << 32)
}
