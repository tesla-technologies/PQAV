// SPDX-License-Identifier: MIT OR Apache-2.0
// src/units.rs
use crate::adts::{hash_audio, split_adts};
use crate::h264::hash_video;
use crate::ts::{pts_dif, Pes, Pmt, PTS_MOD};

pub const REL_MAX: i64 = 1 << 20;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UnitsError {
    #[error("intervalo demasiado largo (rel = {0} tics)")]
    IntervaloDemasiadoLargo(i64),
    #[error("intervalo vacío")]
    IntervaloVacio,
    #[error("tipo de flujo no admitido: 0x{stream_type:02X} en el PID 0x{pid:04X}")]
    TipoNoAdmitido { stream_type: u8, pid: u16 },
    #[error("la PMT no tiene un vídeo H.264")]
    SinVideo,
    #[error("la PMT tiene más de un vídeo o más de un audio")]
    DemasiadosFlujos,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unit {
    pub comp: u8,
    pub pts: u64,
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Interval {
    pub units: Vec<Unit>, // en el orden en que entraron
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    pub stream_type: u8,
    pub lang: String,
    pub audio_type: u8,
    pub pid: u16, // no se firma; sirve para saber a qué componente va cada PES
}

impl Interval {
    pub fn video_count(&self, video_comp: u8) -> usize {
        self.units.iter().filter(|u| u.comp == video_comp).count()
    }
    pub fn base(&self) -> Result<u64, UnitsError> {
        // IntervaloVacio si no hay unidades
        if self.units.is_empty() {
            return Err(UnitsError::IntervaloVacio);
        }
        let p0 = self.units[0].pts;
        let m = self
            .units
            .iter()
            .map(|u| pts_dif(u.pts, p0))
            .min()
            .unwrap_or(0);
        let base = (p0 as i64 + m).rem_euclid(PTS_MOD as i64) as u64;
        Ok(base)
    }
    pub fn rel(&self, base: u64, u: &Unit) -> Result<u32, UnitsError> {
        let r = pts_dif(u.pts, base);
        if !(0..=REL_MAX).contains(&r) {
            return Err(UnitsError::IntervaloDemasiadoLargo(r));
        }
        Ok(r as u32)
    }
}

pub fn find_anchor_pid(pmt: &Pmt) -> Option<u16> {
    // la entrada 0x06 con registro "PQAV"
    for es in &pmt.es {
        if es.stream_type == 0x06 {
            for (tag, data) in &es.descriptors {
                if *tag == 0x05 && data == b"PQAV" {
                    return Some(es.pid);
                }
            }
        }
    }
    None
}

pub fn component_map(pmt: &Pmt, anchor_pid: Option<u16>) -> Result<Vec<Component>, UnitsError> {
    let mut filtradas = Vec::new();
    for es in &pmt.es {
        let es_ancla_por_pid = anchor_pid.is_some() && Some(es.pid) == anchor_pid;
        let es_ancla_por_tipo = es.stream_type == 0x06
            && es
                .descriptors
                .iter()
                .any(|(tag, data)| *tag == 0x05 && data == b"PQAV");

        if es_ancla_por_pid || es_ancla_por_tipo {
            continue;
        }
        filtradas.push(es);
    }

    let mut res = Vec::new();
    let mut tiene_video = false;
    let mut tiene_audio = false;

    for es in filtradas {
        match es.stream_type {
            0x1B => {
                if tiene_video {
                    return Err(UnitsError::DemasiadosFlujos);
                }
                tiene_video = true;
            }
            0x0F => {
                if tiene_audio {
                    return Err(UnitsError::DemasiadosFlujos);
                }
                tiene_audio = true;
            }
            _ => {
                return Err(UnitsError::TipoNoAdmitido {
                    stream_type: es.stream_type,
                    pid: es.pid,
                });
            }
        }

        let mut lang = String::new();
        let mut audio_type = 0u8;

        for (tag, data) in &es.descriptors {
            if *tag == 0x0A && data.len() >= 3 {
                if let Ok(s) = std::str::from_utf8(&data[..3]) {
                    lang = s.to_string();
                }
                if data.len() >= 4 {
                    audio_type = data[3];
                }
                break;
            }
        }

        res.push(Component {
            stream_type: es.stream_type,
            lang,
            audio_type,
            pid: es.pid,
        });
    }

    if !tiene_video {
        return Err(UnitsError::SinVideo);
    }

    Ok(res)
}

pub fn map_tuples(comps: &[Component]) -> Vec<(u8, String, u8)> {
    // lo que va en la carga
    comps
        .iter()
        .map(|c| (c.stream_type, c.lang.clone(), c.audio_type))
        .collect()
}

pub fn parse_pes_to_intervals(
    raw_pes_list: &[(u16, Pes)],
    video_pid: u16,
    audio_pid: Option<u16>,
) -> Result<Vec<Interval>, UnitsError> {
    let mut intervalos = Vec::new();
    let mut abierto = Interval::default();

    for (pid, pes) in raw_pes_list {
        if *pid == video_pid {
            let hash = hash_video(&pes.payload).map_err(|_| UnitsError::SinVideo)?;
            let pts = pes.pts.ok_or(UnitsError::IntervaloVacio)?;
            let unit = Unit { comp: 0, pts, hash };

            // Regla del apartado 6 del Doc 02: al intentar meter la 7.ª unidad de vídeo, se cierra el intervalo.
            if abierto.video_count(0) == 6 {
                intervalos.push(std::mem::take(&mut abierto));
            }
            abierto.units.push(unit);
        } else if Some(*pid) == audio_pid {
            let tramas = split_adts(&pes.payload).map_err(|_| UnitsError::IntervaloVacio)?;
            let base_pts = pes.pts.ok_or(UnitsError::IntervaloVacio)?;
            for (k, trama) in tramas.iter().enumerate() {
                let pts = (base_pts + 1920 * k as u64) % PTS_MOD;
                let hash = hash_audio(trama);
                let unit = Unit { comp: 1, pts, hash };
                abierto.units.push(unit);
            }
        }
    }

    if !abierto.units.is_empty() {
        intervalos.push(abierto);
    }

    Ok(intervalos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ts::parse_pmt;

    fn u(comp: u8, pts: u64) -> Unit {
        Unit {
            comp,
            pts,
            hash: [0; 32],
        }
    }

    #[test]
    fn m4_base_y_rel_con_b_frames() {
        let iv = Interval {
            units: vec![u(0, 133_200), u(0, 126_000), u(0, 129_600), u(1, 124_080)],
        };

        let base = iv.base().unwrap();
        assert_eq!(base, 124_080);
        assert_eq!(iv.rel(base, &iv.units[0]), Ok(9_120));
        assert_eq!(iv.rel(base, &iv.units[3]), Ok(0));
        assert_eq!(iv.video_count(0), 3);
    }

    #[test]
    fn m4_base_con_vuelta_de_pts() {
        let m = 1u64 << 33;
        let iv = Interval {
            units: vec![u(0, 1_800), u(0, m - 1_800)],
        };

        let base = iv.base().unwrap();
        assert_eq!(base, m - 1_800);
        assert_eq!(iv.rel(base, &iv.units[0]), Ok(3_600));

        let lejos = Interval {
            units: vec![u(0, 0), u(0, (1 << 20) + 1)],
        };
        let b = lejos.base().unwrap();
        assert_eq!(
            lejos.rel(b, &lejos.units[1]),
            Err(UnitsError::IntervaloDemasiadoLargo((1 << 20) + 1))
        );
    }

    #[test]
    fn m4_mapa_de_componentes() {
        let pmt2: [u8; 43] = [
            0x02, 0xB0, 0x28, 0x00, 0x01, 0xC1, 0x00, 0x00, 0xE1, 0x00, 0xF0, 0x00, 0x1B, 0xE1,
            0x00, 0xF0, 0x00, 0x0F, 0xE1, 0x01, 0xF0, 0x06, 0x0A, 0x04, 0x73, 0x70, 0x61, 0x00,
            0x06, 0xFF, 0xF0, 0xF0, 0x06, 0x05, 0x04, 0x50, 0x51, 0x41, 0x56, 0x57, 0x15, 0xF0,
            0x5F,
        ];
        let pmt = parse_pmt(&pmt2).unwrap();
        assert_eq!(find_anchor_pid(&pmt), Some(0x1FF0));
        let comps = component_map(&pmt, Some(0x1FF0)).unwrap();
        assert_eq!(
            map_tuples(&comps),
            vec![(27, String::new(), 0), (15, "spa".to_string(), 0)]
        );
        assert_eq!(comps[1].pid, 0x0101);
    }

    #[test]
    fn m4_mapa_con_audio_type_3() {
        use crate::ts::{EsEntry, Pmt};

        let pmt = Pmt {
            pcr_pid: 0x0100,
            version: 0,
            es: vec![
                EsEntry {
                    stream_type: 0x1B, // Vídeo H.264
                    pid: 0x0100,
                    descriptors: vec![],
                },
                EsEntry {
                    stream_type: 0x0F, // Audio AAC
                    pid: 0x0101,
                    descriptors: vec![
                        // Descriptor 0x0A de idioma: "spa" + audio_type (3)
                        (0x0A, vec![b's', b'p', b'a', 3]),
                    ],
                },
            ],
        };
        let comps = component_map(&pmt, None).unwrap();
        assert_eq!(
            map_tuples(&comps),
            vec![(27, String::new(), 0), (15, "spa".to_string(), 3)]
        );
    }

    #[test]
    fn m4_mapa_con_dos_descriptores_de_idioma() {
        use crate::ts::{EsEntry, Pmt};

        let pmt = Pmt {
            pcr_pid: 0x0100,
            version: 0,
            es: vec![
                EsEntry {
                    stream_type: 0x1B, // Vídeo H.264
                    pid: 0x0100,
                    descriptors: vec![],
                },
                EsEntry {
                    stream_type: 0x0F, // Audio AAC
                    pid: 0x0101,
                    descriptors: vec![
                        // Primer descriptor: "eng"
                        (0x0A, vec![b'e', b'n', b'g', 0]),
                        // Segundo descriptor: "spa"
                        (0x0A, vec![b's', b'p', b'a', 1]),
                    ],
                },
            ],
        };

        let comps = component_map(&pmt, None).unwrap();

        // Debe seleccionar el primer descriptor ("eng")
        assert_eq!(
            map_tuples(&comps),
            vec![(27, String::new(), 0), (15, "eng".to_string(), 0)]
        );
    }
}
